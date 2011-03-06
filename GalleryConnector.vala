/* Copyright 2009-2010 Nicolas Toromanoff nicolas@toromanoff.org
 *
 * This software is licensed under the GNU LGPL (version 2.1 or later).
 * See the COPYING file in this distribution. 
 */
public class GalleryService : Object, Spit.Pluggable, Spit.Publishing.Service {
    public int get_pluggable_interface(int min_host_interface, int max_host_interface) {
        return Spit.negotiate_interfaces(min_host_interface, max_host_interface,
            Spit.Publishing.CURRENT_INTERFACE);
    }

    public unowned string get_id() {
        return "org.yorba.shotwell.publishing.gallery2";
    }

    public unowned string get_pluggable_name() {
        return "Gallery2";
    }

    public void get_info(out Spit.PluggableInfo info) {
        info.authors = "Nicolas Toromanoff";
        info.copyright = _("");
        //info.translators = Resources.TRANSLATORS;
        //info.version = _VERSION;
        //info.website_name = Resources.WEBSITE_NAME;
        //info.website_url = Resources.WEBSITE_URL;
        //info.is_license_wordwrapped = false;
        //info.license = Resources.LICENSE;
    }

    public void activation(bool enabled) {
    }

    public Spit.Publishing.Publisher create_publisher(Spit.Publishing.PluginHost host) {
        return new Publishing.Gallery2.GalleryPublisher(this, host);
    }

    public Spit.Publishing.Publisher.MediaType get_supported_media() {
        return (Spit.Publishing.Publisher.MediaType.PHOTO |
            Spit.Publishing.Publisher.MediaType.VIDEO);
    }
}


namespace Publishing.Gallery2 {
private const string SERVICE_NAME = "Gallery2";
private const string SERVICE_WELCOME_MESSAGE = 
    _("You are not currently logged into your Gallery.\n\nYou must have already signed up for a Gallery account to complete the login process. During login you will have to specifically authorize Shotwell Connect to link to your Gallery account.");
private const string DEFAULT_ALBUM_DIR = _("Shotwell");
private const string DEFAULT_ALBUM_TITLE = _("Shotwell default directory");
private const string CONFIG_NAME = "gallery";

private struct AlbumPerms {
    bool add;
    bool write;
    bool del_alb;
    bool create_sub;
}

private struct AlbumInfo {
    string extrafields;
}

private class Album {
    /* info from GalleryWeb */
    public string title;
    public string name;
    public string summary;
    public string  parentname;
    public AlbumPerms perms;
    public AlbumInfo  info ;
    
    
    public Album() {
    }
}
   
// not a struct because we want reference semantics
private class PublishingParameters {
    public string album_name;
    public string album_dir;
    public string album_title;
    public string parent_name;
    
    public PublishingParameters.to_new_album(string parent_name, string new_album_dir, string new_album_title) {
        this.album_name = null;
        this.parent_name= parent_name;
        this.album_dir = new_album_dir;
        this.album_title = new_album_title;
    }
    
    public PublishingParameters.to_existing_album(string dirname) {
      this.album_name = dirname ;
    }
    
    public bool is_to_new_album() {
        return (album_name == null);
    }
    
    // converts a publish-to-new-album parameters object into a publish-to-existing-album
    // parameters object
    public void convert(string album_name) {
        assert(is_to_new_album());
        this.album_name = album_name;
    }
}

private Album[] extract_gallery_albums(string document_root) {
    Album[] result = new Album[0];
    Album currentAlbum = null;
    string[] lines;
    int nbAlbums = 0;
    int albumIdx = 1; /* as first album is the 1 */
    
    currentAlbum = new Album();
    lines=document_root.split("\n");
    foreach (string line in lines) {
        string[] line_splitted;
        string[] command_splitted;
      line_splitted = line.split("=");
      command_splitted = line_splitted[0].split(".");
      
      //maybe not the best way. We fill the temp variables title, name, summary, parentname, perms and info, and when the album index is incremetanted we save it.;
      switch (command_splitted[0]) {
        case "album" :
            if(command_splitted[command_splitted.length -1].to_int() != albumIdx) {
                /* New album description is just found */
                albumIdx++;
                /* add previous album to the result Array */
                result += currentAlbum ;
                /* create a new Album */
                currentAlbum = new Album();
            }
            switch (command_splitted[1]) {
                case "name" :
                    currentAlbum.name = line_splitted[1];
                    break;
                case "title" :
                    currentAlbum.title = line_splitted[1];
                    break;
                case "summary" :
                    currentAlbum.summary = line_splitted[1];
                    break;
                case "parent" :
                    currentAlbum.parentname = line_splitted[1];
                    break;
                case "perms" :
                    switch (command_splitted[2]) {
                        case "add":
                            currentAlbum.perms.add = line_splitted[1].to_bool();
                        break;
                        case "write":
                            currentAlbum.perms.write = line_splitted[1].to_bool();
                        break;
                        case "del_alb":
                            currentAlbum.perms.del_alb = line_splitted[1].to_bool();
                        break;
                        case "create_sub":
                            currentAlbum.perms.create_sub = line_splitted[1].to_bool();
                        break;
                    }                    
                    break;
                case "info" :
                    if (command_splitted[2] == "extrafields") {
                        currentAlbum.info.extrafields = line_splitted[1];
                    }
                    break;
                default :
                    // TODO: log 
                    break;
            }
            break;
        case "album_count":
            nbAlbums = line_splitted[1].to_int();
            break;
        default :
            // TODO: log 
            break; 
        }
    }
    // save last album
    result += currentAlbum ;

    return result;
}

public class GalleryPublisher : Spit.Publishing.Publisher, GLib.Object {
    private weak Spit.Publishing.PluginHost host = null;
    private Spit.Publishing.ProgressCallback progress_reporter = null;
    private weak Spit.Publishing.Service service = null;
    private bool running = false;
    private Session session;
    private string? username = null;
    private Album[] albums = null;
    private PublishingParameters parameters = null;
    private Spit.Publishing.Publisher.MediaType media_type = Spit.Publishing.Publisher.MediaType.NONE;

    public GalleryPublisher(Spit.Publishing.Service service,
        Spit.Publishing.PluginHost host) {
        this.service = service;
        this.host = host;
        this.session = new Session();
        
        // Ticket #3212 - Only display the size chooser if we're uploading a
        // photograph, since resizing of video isn't supported.
        //
        // Find the media types involved. We need this to decide whether
        // to show the size combobox or not.
        foreach(Spit.Publishing.Publishable p in host.get_publishables()) {
            media_type |= p.get_media_type();
        }         
    }
    
    public bool is_running() {
        return running;
    }
    
    public Spit.Publishing.Service get_service() {
        return service;
    }
    
    public void start() {
        if (is_running())
            return;

        if (host == null)
            error("GalleryPublisher: start( ): can't start; this publisher is not restartable.");

        debug("GalleryPublisher: starting interaction.");
        
        running = true;

        if (is_persistent_session_available()) {
            username = get_persistent_username();
            session.authenticate(get_persistent_auth_token(), get_persistent_username());
            do_fetch_account_information();
        } else {
            do_show_service_welcome_pane();
        }
    }
    
    public void stop() {
        debug("PicasaPublisher: stop( ) invoked.");

        host = null;
        running = false;
    }
    
    
}

internal class Session : Publishing.RESTSupport.Session {
    private string? password=null;
    private string? username=null;
    private string? url=null;
    private string? auth_token=null;
    private string? cookie=null;
    
    public Session() {
    }
    
    public bool is_authenticated() {
        return (password != null);
    }
}
}
