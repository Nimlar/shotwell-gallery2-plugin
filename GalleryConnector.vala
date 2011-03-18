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
internal class PublishingParameters {
    public const int ORIGINAL_SIZE = -1;
    
    public string album_name;
    public string album_dir;
    public string album_title;
    public string parent_name;
    public int photo_major_axis_size;
        
    public PublishingParameters.to_new_album(int photo_major_axis_size, string parent_name, string new_album_dir, string new_album_title) {
        this.photo_major_axis_size = photo_major_axis_size;
        this.album_name = null;
        this.parent_name= parent_name;
        this.album_dir = new_album_dir;
        this.album_title = new_album_title;
    }
    
    public PublishingParameters.to_existing_album(int photo_major_axis_size, string dirname) {
      this.photo_major_axis_size = photo_major_axis_size;
      this.album_name = dirname ;
    }
    
    public bool is_to_new_album() {
        return (album_name == null);
    }
    
    public int get_photo_major_axis_size() {
        return photo_major_axis_size;
    }

    public string get_album_name() {
        assert(is_to_new_album());
        return album_name;
    }

    // converts a publish-to-new-album parameters object into a publish-to-existing-album
    // parameters object
    public void convert(string album_name) {
        assert(is_to_new_album());
        this.album_name = album_name;
    }

}

private class BaseGalleryTransaction : Publishing.RESTSupport.Transaction {
    public BaseGalleryTransaction(Session session, string endpoint_url) {
        base.with_endpoint_url(session, endpoint_url, Publishing.RESTSupport.HttpMethod.POST);
        
        add_argument("g2_controller", "remote:GalleryRemote");
    }
    
    public int check_gallery_response() {
        string[] lines ;
        string? document = this.get_response() ;
        if(document != null) {
          lines=document.split("\n");
          foreach (string line in lines) {
              string[] line_splitted;
              
              line_splitted = line.split("=");
              if(line_splitted[0] == "status") {
                  return line_splitted[1].to_int();
              }
          }
        }
        return 999 ;
    }
    
    // Helper methode get the auth token from an answer
    public string find_auth_token() {
        string[] lines ;
        string document = this.get_response() ;

        lines=document.split("\n");
        
        foreach (string line in lines) {
            string[] line_splitted;
            
            line_splitted = line.split("=");
            if(line_splitted[0] == "auth_token") {
                return line_splitted[1];
            }
        }
        return "" ;
    
    }

}

private class AuthenticatedTransaction : BaseGalleryTransaction {
    public AuthenticatedTransaction(Session session, string endpoint_url) {
        base(session, endpoint_url);

        add_argument("g2_authToken", session.get_auth_token());
        add_header("Cookie", session.get_cookie());
    }
}

private class LoginTransaction : BaseGalleryTransaction {
    private string url;
    private string username;
    private string password;
    
    public LoginTransaction(Session session, string url, string username, string password) {
        base(session, url);
        this.url = url ;
        this.username = username ;
        this.password = password ; 
        add_argument("g2_form[cmd]", "login");
        add_argument("g2_form[uname]", username);
        add_argument("g2_form[password]", password);
    }
    
    public string get_username() {
        return this.username;
    }
    
    public string get_password() {
        return this.password;
    }

    public string get_gallery_url() {
        return this.url;
    }
    
    // Helper method: retrieves Cookie rom RESTTransaction received
    // same as the one from PiwigoConnector.vala
    public string get_cookie_from_transaction() {
        string? cookie = this.get_header_response("Set-Cookie");
        if ((cookie != null) && (cookie != "")) {
            string tmp = cookie.rstr("GALLERYSID=");
            string[] values = tmp.split(";");
            string gallery_id = values[0];
            return gallery_id;
        } else {
            return "";
        }
    }    
}


private class AlbumDirectoryTransaction : AuthenticatedTransaction {
    public AlbumDirectoryTransaction(Session session, string url) {
        base(session, url);
        add_argument("g2_form[cmd]", "fetch-albums-prune");
    }
}

private class AlbumCreationTransaction : AuthenticatedTransaction {
    public AlbumCreationTransaction(Session session, string url, PublishingParameters parameters) {
        base(session, url);

        add_argument("g2_form[cmd]", "new-album");
        add_argument("g2_form[set_albumName]", parameters.parent_name);
        add_argument("g2_form[newAlbumName]", parameters.album_dir);
        add_argument("g2_form[newAlbumTitle]", parameters.album_title);
        add_argument("g2_form[newAlbumDesc]", "");
    }
}


private class UploadTransaction : AuthenticatedTransaction {
    private Session session_copy = null;
    private Spit.Publishing.Publishable  publishable;
    private string mime_type;
    private GLib.HashTable<string, string> binary_disposition_table = null;
        
    public UploadTransaction(Session session, PublishingParameters params, 
                                       Spit.Publishing.Publishable  publishable) {
        base.with_endpoint_url(session, session.get_gallery_url());
        assert(session.is_authenticated());
        
        this.session_copy = session;
        this.publishable = publishable;
        this.mime_type = (publishable.get_media_type() == Spit.Publishing.Publisher.MediaType.VIDEO) ?
            "video/mpeg" : "image/jpeg";
        debug("GalleryUploadTransaction upload file %s", publishable.get_publishing_name());
        
        add_argument("g2_form[cmd]", "add-item");
        add_argument("g2_form[protocol_version]", "2.10");
        add_argument("g2_form[set_albumName]", params.album_name);
        // TODO: add_argument("g2_form[caption]", "");
        add_argument("g2_form[userfile_name]", publishable.get_publishing_name());
        add_argument("g2_form[force_filename]", publishable.get_publishing_name());
        add_argument("g2_form[auto_rotate]", "yes");
        add_argument("g2_authToken", session.get_auth_token());
        add_argument("g2_controller", "remote.GalleryRemote");
        
        GLib.HashTable<string, string> disposition_table =
            new GLib.HashTable<string, string>(GLib.str_hash, GLib.str_equal);
        disposition_table.insert("filename", publishable.get_publishing_name());
        disposition_table.insert("name", "g2_userfile");
        set_binary_disposition_table(disposition_table);
    }
    
    protected new void set_binary_disposition_table(GLib.HashTable<string, string> new_disp_table) {
        binary_disposition_table = new_disp_table;
    }
    
    // Need to copy and paste this method to add the cookie header to the sent message.
    public override void execute() throws Spit.Publishing.PublishingError {

        Publishing.RESTSupport.Argument[] request_arguments = get_arguments();
        assert(request_arguments.length > 0);

        // create the multipart request container
        Soup.Multipart message_parts = new Soup.Multipart("multipart/form-data");

        // attach each REST argument as its own multipart formdata part
        foreach (Publishing.RESTSupport.Argument arg in request_arguments)
            message_parts.append_form_string(arg.key, arg.value);

        // attempt to read the binary image data from disk
        string photo_data;
        size_t data_length;
        try {
            FileUtils.get_contents(publishable.get_serialized_file().get_path(), out photo_data, out data_length);
        } catch (FileError e) {
            error("PhotoUploadTransaction: couldn't read data from file '%s'", publishable.get_serialized_file().get_path());
        }

        // get the sequence number of the part that will soon become the binary image data
        // part
        int image_part_num = message_parts.get_length();

        // bind the binary image data read from disk into a Soup.Buffer object so that we
        // can attach it to the multipart request, then actaully append the buffer
        // to the multipart request. Then, set the MIME type for this part.
        Soup.Buffer bindable_data = new Soup.Buffer(Soup.MemoryUse.COPY, photo_data, data_length);
        message_parts.append_form_file("", publishable.get_serialized_file().get_path(), mime_type, bindable_data);

        // set up the Content-Disposition header for the multipart part that contains the
        // binary image data
        unowned Soup.MessageHeaders image_part_header;
        unowned Soup.Buffer image_part_body;
        message_parts.get_part(image_part_num, out image_part_header, out image_part_body);
        image_part_header.set_content_disposition("form-data", binary_disposition_table);

        // create a message that can be sent over the wire whose payload is the multipart container
        // that we've been building up
        Soup.Message outbound_message = Soup.form_request_new_from_multipart(get_endpoint_url(), message_parts);
        outbound_message.request_headers.append("Cookie", session_copy.get_cookie());
        set_message(outbound_message);

        // send the message and get its response
        set_is_executed(true);
        send();
    }
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

    // Helper method: retrieve internal name for the newly created diretory
    private string extract_new_created_album_name(Publishing.RESTSupport.Transaction txn) {
        string[] lines ;
        string document = txn.get_response() ;
        
        lines=document.split("\n");
        
        foreach (string line in lines) {
            string[] line_splitted;
            
            line_splitted = line.split("=");
            if(line_splitted[0] == "album_name") {
                return line_splitted[1];
            }
        }
        return "" ;
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
    
    internal string? get_persistent_username() {
        return host.get_config_string("username", null);
    }
    
    internal string? get_persistent_password() {
        return host.get_config_string("password", null);
    }
    
    internal string? get_persistent_url() {
        return host.get_config_string("url", null);
    }
    
    internal string? get_persistent_auth_token() {
        return host.get_config_string("auth_token", null);
    }
    
    internal string? get_persistent_cookie() {
        return host.get_config_string("cookie", null);
    }
                
    internal void set_persistent_username(string username) {
        host.set_config_string("username", username);
    }
    
    internal void set_persistent_password(string password) {
        host.set_config_string("password", password);
    }
    
    internal void set_persistent_url(string url) {
        host.set_config_string("url", url);
    }
        
    internal void set_persistent_auth_token(string auth_token) {
        host.set_config_string("auth_token", auth_token);
    }
    
    internal void set_persistent_cookie(string cookie) {
        host.set_config_string("cookie", cookie);
    }
    
    internal void invalidate_persistent_session() {
        debug("invalidating persisted Gallery session.");

        host.unset_config_key("username");
        host.unset_config_key("password");
        host.unset_config_key("url");
    }
    
    internal bool is_persistent_session_available() {
        return (get_persistent_username() != null && get_persistent_password() != null && get_persistent_url() != null);
    }

    
    public bool is_running() {
        return running;
    }
    
    public Spit.Publishing.Service get_service() {
        return service;
    }

    private void do_show_success_pane() {
        debug("ACTION: showing success pane.");

        host.set_service_locked(false);
        host.install_success_pane();
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
            session.authenticate(get_persistent_url(), get_persistent_username(), get_persistent_password(), get_persistent_auth_token(), get_persistent_cookie());
            do_fetch_account_information();
        } else {
            do_show_service_welcome_pane();
        }
    }
    
    public void stop() {
        debug("GalleryPublisher: stop( ) invoked.");

        host = null;
        running = false;
    }
    
    private void on_service_welcome_login() {
        if (!is_running())
            return;
        
        debug("EVENT: user clicked 'Login' in welcome pane.");

        do_show_credentials_pane(CredentialsPane.Mode.INTRO);
    }
    
    private void on_initial_album_fetch_complete(Publishing.RESTSupport.Transaction txn) {
        txn.completed.disconnect(on_initial_album_fetch_complete);
        txn.network_error.disconnect(on_initial_album_fetch_error);

        if (!is_running())
            return;

        debug("EVENT: finished fetching account and album information.");

        do_parse_and_display_account_information((AlbumDirectoryTransaction) txn);
    }

    private void on_initial_album_fetch_error(Publishing.RESTSupport.Transaction bad_txn,
        Spit.Publishing.PublishingError err) {
        bad_txn.completed.disconnect(on_initial_album_fetch_complete);
        bad_txn.network_error.disconnect(on_initial_album_fetch_error);

        if (!is_running())
            return;

        debug("EVENT: fetching account and album information failed; response = '%s'.",
            bad_txn.get_response());
            
        host.post_error(err);

    }
    private void on_upload_status_updated(int file_number, double completed_fraction) {
        if (!is_running())
            return;

        debug("EVENT: uploader reports upload %.2f percent complete.", 100.0 * completed_fraction);

        assert(progress_reporter != null);

        progress_reporter(file_number, completed_fraction);
    }
    
    private void on_upload_complete(Publishing.RESTSupport.BatchUploader uploader,
        int num_published) {
        if (!is_running())
            return;

        debug("EVENT: uploader reports upload complete; %d items published.", num_published);

        uploader.upload_complete.disconnect(on_upload_complete);
        uploader.upload_error.disconnect(on_upload_error);

        do_show_success_pane();
    }

    private void on_upload_error(Publishing.RESTSupport.BatchUploader uploader,
        Spit.Publishing.PublishingError err) {
        if (!is_running())
            return;

        debug("EVENT: uploader reports upload error = '%s'.", err.message);

        uploader.upload_complete.disconnect(on_upload_complete);
        uploader.upload_error.disconnect(on_upload_error);

        host.post_error(err);
    }

    
    private void do_show_service_welcome_pane() {
        debug("ACTION: showing service welcome pane.");

        host.install_welcome_pane(SERVICE_WELCOME_MESSAGE, on_service_welcome_login);
    }
    
    private void do_show_credentials_pane(CredentialsPane.Mode mode) {
        debug("ACTION: showing credentials capture pane in %s mode.", mode.to_string());
        
        CredentialsPane creds_pane = new CredentialsPane(host, mode);
        creds_pane.go_back.connect(on_credentials_go_back);
        creds_pane.login.connect(on_credentials_login);

        host.install_dialog_pane(creds_pane);
    }
    
    // ACTION: given a username and password, run a REST transaction over the network to
    //         log a user into the Gallery Web Albums service
    private void do_network_login(string gallery_url, string username, string password) {
        host.install_login_wait_pane();

        string my_url = gallery_url;

        if(!my_url.has_suffix(".php")) {
            if(!my_url.has_suffix("/")) {
                my_url = my_url + "/";
            }
            my_url = my_url + "main.php";
        }

        if(!my_url.has_prefix("http://") && !my_url.has_prefix("https://")) {
            my_url = "http://" + my_url;
        }


        LoginTransaction login_trans = new LoginTransaction(session, my_url, username, password);
        login_trans.network_error.connect(on_login_network_error);
        login_trans.completed.connect(on_login_network_complete);
        try {
            login_trans.execute();
        } catch (Spit.Publishing.PublishingError err) {
            host.post_error(err);
        }
    }

    // ACTION: run a REST transaction over the network to fetch the user's account information
    //         (e.g. the names of the user's albums and their corresponding REST URLs). While
    //         the network transaction is running, display a wait pane with an info message in
    //         the publishing dialog.
    private void do_fetch_account_information() {
        debug("ACTION: fetching account and album information.");
        //TODO: TOREMOVE get_host().install_pane(new AccountFetchWaitPane());
        //TODO: TOREMOVE get_host().lock_service();
        
        host.install_account_fetch_wait_pane();
        host.set_service_locked(true);
        
        AlbumDirectoryTransaction directory_trans =
            new AlbumDirectoryTransaction(session, session.get_gallery_url() );
        directory_trans.network_error.connect(on_initial_album_fetch_error);
        directory_trans.completed.connect(on_initial_album_fetch_complete);
        try {
            directory_trans.execute();
        } catch (Spit.Publishing.PublishingError err) {
            on_initial_album_fetch_error(directory_trans, err);
        }
    }
    
    private void do_parse_and_display_account_information(AlbumDirectoryTransaction transaction) {
        debug("ACTION: fetching account and album information.");

        string response_doc;
        
        // TODO: add try catch
        response_doc = transaction.get_response();
        
        albums = extract_gallery_albums(response_doc);


        do_show_publishing_options_pane();
    }
    
    // ACTION: run a REST transaction over the network to create a new album with the parameters
    //         specified in 'parameters'. Display a wait pane with an info message in the
    //         publishing dialog while the transaction is running. This action should only
    //         occur if 'parameters' describes a publish-to-new-album operation.
    private void do_create_album(PublishingParameters parameters) {
        assert(parameters.is_to_new_album());
        debug("ACTION: creating new album '%s' on remote server.", parameters.get_album_name());

        host.install_static_message_pane(_("Creating album..."));

        host.set_service_locked(true);

        AlbumCreationTransaction creation_trans = new AlbumCreationTransaction(session, session.get_gallery_url(),
            parameters);
        creation_trans.network_error.connect(on_album_creation_error);
        creation_trans.completed.connect(on_album_creation_complete);
        try{
            creation_trans.execute();
        } catch (Spit.Publishing.PublishingError err) {
            host.post_error(err);
        }
    }
    
    // ACTION: run a REST transaction over the network to upload the user's photos to the remote
    //         endpoint. Display a progress pane while the transaction is running.
    private void do_upload() {
        debug("ACTION: uploading media items to remote server.");

        host.set_service_locked(true);
        
        progress_reporter = host.serialize_publishables(parameters.get_photo_major_axis_size());

        Spit.Publishing.Publishable[] publishables = host.get_publishables();
        Uploader uploader = new Uploader(session, publishables, parameters);

        uploader.upload_complete.connect(on_upload_complete);
        uploader.upload_error.connect(on_upload_error);

        uploader.upload(on_upload_status_updated);
    }
    
    // EVENT: triggered when the user clicks "Logout" in the publishing options pane
    private void on_publishing_options_logout() {
        if (!is_running())
            return;

        session.deauthenticate();

        do_show_service_welcome_pane();
    }
    
    // EVENT: triggered when the user clicks "Publish" in the publishing options pane
    private void on_publishing_options_publish(PublishingParameters parameters) {
        if (!is_running())
            return;
        
        this.parameters = parameters;

        if (parameters.is_to_new_album()) { 
            do_create_album(parameters);
        } else {
            do_upload();
        }
        
    }
    private void on_album_creation_complete(Publishing.RESTSupport.Transaction txn) {
        txn.completed.disconnect(on_album_creation_complete);
        txn.network_error.disconnect(on_album_creation_error);
        
        if (!is_running())
            return;
            
        debug("EVENT: finished creating album on remote server.");
        
        parameters.convert(extract_new_created_album_name(txn));
        do_upload();

        do_upload();
    }

    private void on_album_creation_error(Publishing.RESTSupport.Transaction bad_txn,
        Spit.Publishing.PublishingError err) {
        bad_txn.completed.disconnect(on_album_creation_complete);
        bad_txn.network_error.disconnect(on_album_creation_error);
        
        if (!is_running())
            return;
            
        debug("EVENT: creating album on remote server failed; response = '%s'.",
            bad_txn.get_response());

        host.post_error(err);
    }

    private void on_credentials_go_back() {
        if (!is_running())
            return;
            
        debug("EVENT: user clicked 'Go Back' in credentials pane.");

        do_show_service_welcome_pane();
    }

    private void on_credentials_login(string url, string username, string password) {
        if (!is_running())
            return;    
    
        debug("EVENT: user clicked 'Login' in credentials pane.");

        this.username = username;

        do_network_login(url, username, password);
    }
    
    private void do_show_publishing_options_pane() {
        debug("ACTION: showing publishing options pane.");
        
        PublishingOptionsPane opts_pane = new PublishingOptionsPane(host, username, albums, media_type);
        opts_pane.publish.connect(on_publishing_options_publish);
        opts_pane.logout.connect(on_publishing_options_logout);
        host.install_dialog_pane(opts_pane);

        host.set_service_locked(false); 
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
    
    public override bool is_authenticated() {
        return (password != null);
    }
    
    public void authenticate(string gallery_url, string username, string password, string auth_token, string cookie) {
        this.url = gallery_url;
        this.password = password;
        this.username = username;
        this.auth_token = auth_token;
        this.cookie = cookie ;
        
        notify_authenticated();
    }
    
    public void deauthenticate() {
        url = null;
        password = null;
        username = null;
        cookie = null;
        auth_token = null;
    }

    public string get_username() {
        return username;
    }

    public string get_password() {
        return password;
    }
    
    public string get_gallery_url() {
        return url;
    }
    
    public string get_auth_token() {
        return auth_token;
    }
    
    public string get_cookie() {
        return cookie;
    }
    
}


internal class CredentialsPane : Spit.Publishing.DialogPane, GLib.Object {
    public enum Mode {
        INTRO,
        FAILED_RETRY,
        NOT_SET_UP,
        ADDITIONAL_SECURITY;

        public string to_string() {
            switch (this) {
                case Mode.INTRO:
                    return "INTRO";

                case Mode.FAILED_RETRY:
                    return "FAILED_RETRY";

                case Mode.NOT_SET_UP:
                    return "NOT_SET_UP";

                case Mode.ADDITIONAL_SECURITY:
                    return "ADDITIONAL_SECURITY";

                default:
                    error("unrecognized CredentialsPane.Mode enumeration value");
            }
        }
    }

    private LegacyCredentialsPane wrapped = null;

    public signal void go_back();
    public signal void login(string url, string uname, string password);

    public CredentialsPane(Spit.Publishing.PluginHost host, Mode mode = Mode.INTRO,
        string? username = null) {
            wrapped = new LegacyCredentialsPane(host, mode, username);
    }
    
    protected void notify_go_back() {
        go_back();
    }
    
    protected void notify_login(string url, string uname, string password) {
        login(url, uname, password);
    }

    public Gtk.Widget get_widget() {
        return wrapped;
    }
    
    public Spit.Publishing.DialogPane.GeometryOptions get_preferred_geometry() {
        return Spit.Publishing.DialogPane.GeometryOptions.NONE;
    }
    
    public void on_pane_installed() {        
        wrapped.go_back.connect(notify_go_back);
        wrapped.login.connect(notify_login);
        
        wrapped.installed();
    }
    
    public void on_pane_uninstalled() {
        wrapped.go_back.disconnect(notify_go_back);
        wrapped.login.disconnect(notify_login);
    }
}

internal class LegacyCredentialsPane : Gtk.VBox {
    private const string INTRO_MESSAGE = _("Enter the url of you Gallery installation and username/password associated with this installation.");
    private const string FAILED_RETRY_MESSAGE = _("FAILED_RETRY_MESSAGE");
    private const string NOT_SET_UP_MESSAGE = _("NOT_SET_UP_MESSAGE");
    private const string ADDITIONAL_SECURITY_MESSAGE = _("ADDITIONAL_SECURITY_MESSAGE");
    
    private const int UNIFORM_ACTION_BUTTON_WIDTH = 102;
    public const int STANDARD_CONTENT_LABEL_WIDTH = 500;

    private weak Spit.Publishing.PluginHost host = null;
    private Gtk.Entry email_entry;
    private Gtk.Entry password_entry;
    private Gtk.Button login_button;
    private Gtk.Button go_back_button;
    private string? username = null;

    public signal void go_back();
    public signal void login(string url, string uname, string password);

    public LegacyCredentialsPane(Spit.Publishing.PluginHost host, CredentialsPane.Mode mode =
        CredentialsPane.Mode.INTRO, string? username = null) {
        this.host = host;
        this.username = username;

        Gtk.SeparatorToolItem top_space = new Gtk.SeparatorToolItem();
        top_space.set_draw(false);
        Gtk.SeparatorToolItem bottom_space = new Gtk.SeparatorToolItem();
        bottom_space.set_draw(false);
        add(top_space);
        top_space.set_size_request(-1, 40);

        Gtk.Label intro_message_label = new Gtk.Label("");
        intro_message_label.set_line_wrap(true);
        add(intro_message_label);
        intro_message_label.set_size_request(STANDARD_CONTENT_LABEL_WIDTH, -1);
        intro_message_label.set_alignment(0.5f, 0.0f);
        switch (mode) {
            case CredentialsPane.Mode.INTRO:
                intro_message_label.set_text(INTRO_MESSAGE);
            break;

            case CredentialsPane.Mode.FAILED_RETRY:
                intro_message_label.set_markup("<b>%s</b>\n\n%s".printf(_(
                    "Unrecognized User"), FAILED_RETRY_MESSAGE));
            break;

            case CredentialsPane.Mode.NOT_SET_UP:
                intro_message_label.set_markup("<b>%s</b>\n\n%s".printf(_("Account Not Ready"),
                    NOT_SET_UP_MESSAGE));
                Gtk.SeparatorToolItem long_message_space = new Gtk.SeparatorToolItem();
                long_message_space.set_draw(false);
                add(long_message_space);
                long_message_space.set_size_request(-1, 40);
            break;

            case CredentialsPane.Mode.ADDITIONAL_SECURITY:
                intro_message_label.set_markup("<b>%s</b>\n\n%s".printf(_("Additional Security Required"),
                    ADDITIONAL_SECURITY_MESSAGE));
                Gtk.SeparatorToolItem long_message_space = new Gtk.SeparatorToolItem();
                long_message_space.set_draw(false);
                add(long_message_space);
                long_message_space.set_size_request(-1, 40);
            break;
        }

        Gtk.Alignment entry_widgets_table_aligner = new Gtk.Alignment(0.5f, 0.5f, 0.0f, 0.0f);
        Gtk.Table entry_widgets_table = new Gtk.Table(3,2, false);
        Gtk.Label email_entry_label = new Gtk.Label.with_mnemonic(_("_Email address:"));
        email_entry_label.set_alignment(0.0f, 0.5f);
        Gtk.Label password_entry_label = new Gtk.Label.with_mnemonic(_("_Password:"));
        password_entry_label.set_alignment(0.0f, 0.5f);
        email_entry = new Gtk.Entry();
        if (username != null)
            email_entry.set_text(username);
        email_entry.changed.connect(on_email_changed);
        password_entry = new Gtk.Entry();
        password_entry.set_visibility(false);
        entry_widgets_table.attach(email_entry_label, 0, 1, 0, 1,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 6, 6);
        entry_widgets_table.attach(password_entry_label, 0, 1, 1, 2,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 6, 6);
        entry_widgets_table.attach(email_entry, 1, 2, 0, 1,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 6, 6);
        entry_widgets_table.attach(password_entry, 1, 2, 1, 2,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 6, 6);
        go_back_button = new Gtk.Button.with_mnemonic(_("Go _Back"));
        go_back_button.clicked.connect(on_go_back_button_clicked);
        Gtk.Alignment go_back_button_aligner = new Gtk.Alignment(0.0f, 0.5f, 0.0f, 0.0f);
        go_back_button_aligner.add(go_back_button);
        go_back_button.set_size_request(UNIFORM_ACTION_BUTTON_WIDTH, -1);
        login_button = new Gtk.Button.with_mnemonic(_("_Login"));
        login_button.clicked.connect(on_login_button_clicked);
        login_button.set_sensitive(username != null);
        Gtk.Alignment login_button_aligner = new Gtk.Alignment(1.0f, 0.5f, 0.0f, 0.0f);
        login_button_aligner.add(login_button);
        login_button.set_size_request(UNIFORM_ACTION_BUTTON_WIDTH, -1);
        entry_widgets_table.attach(go_back_button_aligner, 0, 1, 2, 3,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 6, 40);
        entry_widgets_table.attach(login_button_aligner, 1, 2, 2, 3,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 6, 40);
        entry_widgets_table_aligner.add(entry_widgets_table);
        add(entry_widgets_table_aligner);

        email_entry_label.set_mnemonic_widget(email_entry);
        password_entry_label.set_mnemonic_widget(password_entry);

        add(bottom_space);
        bottom_space.set_size_request(-1, 40);
    }

    private void on_login_button_clicked() {
        login(email_entry.get_text(), password_entry.get_text());
    }

    private void on_go_back_button_clicked() {
        go_back();
    }

    private void on_email_changed() {
        login_button.set_sensitive(email_entry.get_text() != "");
    }

    public void installed() {
        email_entry.grab_focus();
        password_entry.set_activates_default(true);
        login_button.can_default = true;
        host.set_dialog_default_widget(login_button);
    }
}

internal class PublishingOptionsPane : Spit.Publishing.DialogPane, GLib.Object {
    private LegacyPublishingOptionsPane wrapped = null;

    public signal void publish(PublishingParameters parameters);
    public signal void logout();

    public PublishingOptionsPane(Spit.Publishing.PluginHost host, string username, Album[] albums, Spit.Publishing.Publisher.MediaType media_type) {
        wrapped = new LegacyPublishingOptionsPane(host, username, albums, media_type);
    }
    
    protected void notify_publish(PublishingParameters parameters) {
        publish(parameters);
    }
    
    protected void notify_logout() {
        logout();
    }

    public Gtk.Widget get_widget() {
        return wrapped;
    }
    
    public Spit.Publishing.DialogPane.GeometryOptions get_preferred_geometry() {
        return Spit.Publishing.DialogPane.GeometryOptions.NONE;
    }
    
    public void on_pane_installed() {        
        wrapped.publish.connect(notify_publish);
        wrapped.logout.connect(notify_logout);
        
        wrapped.installed();
    }
    
    public void on_pane_uninstalled() {
        wrapped.publish.disconnect(notify_publish);
        wrapped.logout.disconnect(notify_logout);
    }
}

internal class LegacyPublishingOptionsPane : Gtk.VBox {
    private struct SizeDescription {
        string name;
        int major_axis_pixels;

        SizeDescription(string name, int major_axis_pixels) {
            this.name = name;
            this.major_axis_pixels = major_axis_pixels;
        }
    }

    private const int PACKER_VERTICAL_PADDING = 16;
    private const int PACKER_HORIZ_PADDING = 128;
    private const int INTERSTITIAL_VERTICAL_SPACING = 20;
    private const int ACTION_BUTTON_SPACING = 48;
    private const int ACTION_BUTTON_WIDTH = 128;
    private const string DEFAULT_SIZE_CONFIG_KEY = "default_size";
    private const string LAST_ALBUM_CONFIG_KEY = "last_album";
    
    private Gtk.ComboBox existing_albums_combo;
    private Gtk.Entry new_album_dir_entry ;
    private Gtk.Entry new_album_title_entry ;
    private Gtk.Entry new_album_entry; // TODO REMOVE
    private Gtk.CheckButton public_check;
    private Gtk.ComboBox size_combo;
    private Gtk.RadioButton use_existing_radio;
    private Gtk.RadioButton create_new_radio;
    private Album[] albums;
    private SizeDescription[] size_descriptions;
    private Gtk.Button publish_button;
    private string username;
    private weak Spit.Publishing.PluginHost host;

    public signal void publish(PublishingParameters parameters);
    public signal void logout();

    public LegacyPublishingOptionsPane(Spit.Publishing.PluginHost host, string username, 
        Album[] albums, Spit.Publishing.Publisher.MediaType media_type) {
        this.username = username;
        this.albums = albums;
        this.host = host;
        size_descriptions = create_size_descriptions();

        Gtk.SeparatorToolItem top_pusher = new Gtk.SeparatorToolItem();
        top_pusher.set_draw(false);
        top_pusher.set_size_request(-1, 8);
        add(top_pusher);

        Gtk.Label login_identity_label =
            new Gtk.Label(_("You are logged into Picasa Web Albums as %s.").printf(
            username));

        add(login_identity_label);

        Gtk.VBox vert_packer = new Gtk.VBox(false, 0);
        Gtk.SeparatorToolItem packer_top_padding = new Gtk.SeparatorToolItem();
        packer_top_padding.set_draw(false);
        packer_top_padding.set_size_request(-1, PACKER_VERTICAL_PADDING);

        Gtk.SeparatorToolItem identity_table_spacer = new Gtk.SeparatorToolItem();
        identity_table_spacer.set_draw(false);
        identity_table_spacer.set_size_request(-1, INTERSTITIAL_VERTICAL_SPACING);
        vert_packer.add(identity_table_spacer);

        Gtk.Table main_table = new Gtk.Table(6, 3, false);

        // Ticket #3212, part II - If we're onluy uploading video, alter the         
        // 'will appear in' message to reflect this.          
        Gtk.Label publish_to_label;

        if((media_type & Spit.Publishing.Publisher.MediaType.PHOTO) == 0) 
            publish_to_label = new Gtk.Label(_("Videos will appear in:"));
        else
            publish_to_label = new Gtk.Label(_("Photos will appear in:"));
            
        publish_to_label.set_alignment(0.0f, 0.5f);
        main_table.attach(publish_to_label, 0, 2, 0, 1,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 4, 4);

        Gtk.SeparatorToolItem suboption_indent_spacer = new Gtk.SeparatorToolItem();
        suboption_indent_spacer.set_draw(false);
        suboption_indent_spacer.set_size_request(2, -1);
        main_table.attach(suboption_indent_spacer, 0, 1, 1, 2,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 4, 4);

        use_existing_radio = new Gtk.RadioButton.with_mnemonic(null, _("An _existing album:"));
        use_existing_radio.clicked.connect(on_use_existing_radio_clicked);
        main_table.attach(use_existing_radio, 1, 2, 1, 2,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 4, 4);

        existing_albums_combo = new Gtk.ComboBox.text();
        Gtk.Alignment existing_albums_combo_frame = new Gtk.Alignment(0.0f, 0.5f, 0.0f, 0.0f);
        existing_albums_combo_frame.add(existing_albums_combo);
        main_table.attach(existing_albums_combo_frame, 2, 3, 1, 2,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 4, 4);

        create_new_radio = new Gtk.RadioButton.with_mnemonic(use_existing_radio.get_group(),
            _("A _new album named:"));
        create_new_radio.clicked.connect(on_create_new_radio_clicked);
        main_table.attach(create_new_radio, 1, 2, 2, 3,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 4, 4);

        new_album_entry = new Gtk.Entry();
        new_album_entry.changed.connect(on_new_album_entry_changed);
        main_table.attach(new_album_entry, 2, 3, 2, 3,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 4, 4);

        public_check = new Gtk.CheckButton.with_mnemonic(_("L_ist album in public gallery"));
        main_table.attach(public_check, 2, 3, 3, 4,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 4, 4);

        Gtk.SeparatorToolItem album_size_spacer = new Gtk.SeparatorToolItem();
        album_size_spacer.set_draw(false);
        album_size_spacer.set_size_request(-1, INTERSTITIAL_VERTICAL_SPACING / 2);
        main_table.attach(album_size_spacer, 2, 3, 4, 5,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 4, 4);

        // Ticket #3212 - Only display the size chooser if we're uploading a
        // photograph, since resizing of video isn't supported.
        // 
        // If the media_type argument doesn't tell us we're getting at least
        // one photo, do not create or add these widgets.
        if((media_type & Spit.Publishing.Publisher.MediaType.PHOTO) != 0) {
            Gtk.Label size_label = new Gtk.Label.with_mnemonic(_("Photo _size preset:"));
            size_label.set_alignment(0.0f, 0.5f);
            
            main_table.attach(size_label, 0, 2, 5, 6,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 4, 4);

            size_combo = new Gtk.ComboBox.text();
            foreach(SizeDescription desc in size_descriptions)
                size_combo.append_text(desc.name);
        
            size_combo.set_active(host.get_config_int(DEFAULT_SIZE_CONFIG_KEY, 0));
            Gtk.Alignment size_combo_frame = new Gtk.Alignment(0.0f, 0.5f, 0.0f, 0.0f);
        
            size_combo_frame.add(size_combo);
            main_table.attach(size_combo_frame, 2, 3, 5, 6,
                Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
                Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 4, 4);

            size_label.set_mnemonic_widget(size_combo);
        }

        vert_packer.add(main_table);

        Gtk.SeparatorToolItem table_button_spacer = new Gtk.SeparatorToolItem();
        table_button_spacer.set_draw(false);
        table_button_spacer.set_size_request(-1, INTERSTITIAL_VERTICAL_SPACING);
        vert_packer.add(table_button_spacer);

        Gtk.HBox action_button_layouter = new Gtk.HBox(true, 0);

        Gtk.Button logout_button = new Gtk.Button.with_mnemonic(_("_Logout"));
        logout_button.clicked.connect(on_logout_clicked);
        logout_button.set_size_request(ACTION_BUTTON_WIDTH, -1);
        Gtk.Alignment logout_button_aligner = new Gtk.Alignment(0.5f, 0.5f, 0.0f, 0.0f);
        logout_button_aligner.add(logout_button);
        action_button_layouter.add(logout_button_aligner);
        Gtk.SeparatorToolItem button_spacer = new Gtk.SeparatorToolItem();
        button_spacer.set_draw(false);
        button_spacer.set_size_request(ACTION_BUTTON_SPACING, -1);
        action_button_layouter.add(button_spacer);
        publish_button = new Gtk.Button.with_mnemonic(_("_Publish"));
        publish_button.clicked.connect(on_publish_clicked);
        publish_button.set_size_request(ACTION_BUTTON_WIDTH, -1);
        Gtk.Alignment publish_button_aligner = new Gtk.Alignment(0.5f, 0.5f, 0.0f, 0.0f);
        publish_button_aligner.add(publish_button);
        action_button_layouter.add(publish_button_aligner);

        Gtk.Alignment action_button_wrapper = new Gtk.Alignment(0.5f, 0.5f, 0.0f, 0.0f);
        action_button_wrapper.add(action_button_layouter);

        vert_packer.add(action_button_wrapper);

        Gtk.SeparatorToolItem packer_bottom_padding = new Gtk.SeparatorToolItem();
        packer_bottom_padding.set_draw(false);
        packer_bottom_padding.set_size_request(-1, 2 * PACKER_VERTICAL_PADDING);
        vert_packer.add(packer_bottom_padding);

        Gtk.Alignment vert_packer_wrapper = new Gtk.Alignment(0.5f, 0.5f, 0.0f, 0.0f);
        vert_packer_wrapper.add(vert_packer);

        add(vert_packer_wrapper);
    }

    private void on_publish_clicked() {
        host.set_config_int(DEFAULT_SIZE_CONFIG_KEY, size_combo.get_active());
        int photo_major_axis_size = size_descriptions[size_combo.get_active()].major_axis_pixels;
        //TODO: string album_name;
        if (create_new_radio.get_active()) {
            string new_album_dir = new_album_dir_entry.get_text();
            string new_album_title = new_album_title_entry.get_text();
            publish(new PublishingParameters.to_new_album(photo_major_axis_size,
                                                          albums[existing_albums_combo.get_active()].name, 
                                                          new_album_dir.strip(), 
                                                          new_album_title.strip()));
        } else {
            string album_name = albums[existing_albums_combo.get_active()].name;
            publish(new PublishingParameters.to_existing_album(photo_major_axis_size, album_name));
        }
        //TODO: host.set_config_string(LAST_ALBUM_CONFIG_KEY, album_name);
    }

    private void on_use_existing_radio_clicked() {
        existing_albums_combo.set_sensitive(true);
        new_album_entry.set_sensitive(false);
        existing_albums_combo.grab_focus();
        update_publish_button_sensitivity();
        public_check.set_sensitive(false);
    }

    private void on_create_new_radio_clicked() {
        new_album_entry.set_sensitive(true);
        existing_albums_combo.set_sensitive(false);
        new_album_entry.grab_focus();
        update_publish_button_sensitivity();
        public_check.set_sensitive(true);
    }

    private void on_logout_clicked() {
        logout();
    }

    private void update_publish_button_sensitivity() {
        string album_name = new_album_entry.get_text();
        publish_button.set_sensitive(!(album_name.strip() == "" &&
            create_new_radio.get_active()));
    }

    private void on_new_album_entry_changed() {
        update_publish_button_sensitivity();
    }

    private SizeDescription[] create_size_descriptions() {
        SizeDescription[] result = new SizeDescription[0];

        result += SizeDescription(_("Small (640 x 480 pixels)"), 640);
        result += SizeDescription(_("Medium (1024 x 768 pixels)"), 1024);
        result += SizeDescription(_("Recommended (1600 x 1200 pixels)"), 1600);
        result += SizeDescription(_("Original Size"), PublishingParameters.ORIGINAL_SIZE);

        return result;
    }

    public void installed() {
        int default_album_id = -1;
        string last_album = host.get_config_string(LAST_ALBUM_CONFIG_KEY, "");
        for (int i = 0; i < albums.length; i++) {
            existing_albums_combo.append_text(albums[i].title);
            if (//TODO: albums[i].titl == last_album ||
                (albums[i].title == DEFAULT_ALBUM_TITLE && default_album_id == -1))
                default_album_id = i;
        }

        if (albums.length == 0) {
            existing_albums_combo.set_sensitive(false);
            use_existing_radio.set_sensitive(false);
            create_new_radio.set_active(true);
            new_album_dir_entry.grab_focus();
            new_album_dir_entry.set_text(DEFAULT_ALBUM_DIR);
            new_album_title_entry.set_text(DEFAULT_ALBUM_TITLE);
        } else {
            if (default_album_id >= 0) {
                use_existing_radio.set_active(true);
                existing_albums_combo.set_active(default_album_id);
                //TODO: new_album_entry.set_sensitive(false);   
            } else {
                create_new_radio.set_active(true);
                existing_albums_combo.set_active(0);
                new_album_dir_entry.set_text(DEFAULT_ALBUM_DIR);
                new_album_title_entry.set_text(DEFAULT_ALBUM_TITLE);
                new_album_dir_entry.grab_focus();
            }
        }
        update_publish_button_sensitivity();
    }
}

internal class Uploader : Publishing.RESTSupport.BatchUploader {
    private PublishingParameters parameters;

    public Uploader(Session session, Spit.Publishing.Publishable[] publishables,
        PublishingParameters parameters) {
        base(session, publishables);
        
        this.parameters = parameters;
    }
    
    protected override Publishing.RESTSupport.Transaction create_transaction(
        Spit.Publishing.Publishable publishable) {
        return new UploadTransaction((Session) get_session(), parameters,
            get_current_publishable());
    }
}

}
