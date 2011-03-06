/* Copyright 2009-2010 Nicolas Toromanoff nicolas@toromanoff.org
 *
 * This software is licensed under the GNU LGPL (version 2.1 or later).
 * See the COPYING file in this distribution. 
 */

#if !NO_PUBLISHING

namespace GalleryConnector {
private const string SERVICE_NAME = "Gallery";
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

public class Capabilities : ServiceCapabilities {
    public override string get_name() {
        return SERVICE_NAME;
    }

    public override ServiceCapabilities.MediaType get_supported_media() {
        return MediaType.PHOTO;
    }

    public override ServiceInteractor factory(PublishingDialog host) {
        return new Interactor(host);
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

public class Interactor : ServiceInteractor {
    private Session session = null;
    private bool cancelled = false;
    private Album[] albums = null;
    private PublishingParameters parameters = null;
    private Uploader uploader = null;
    private ProgressPane progress_pane = null;
    
    public Interactor(PublishingDialog host) {
        base(host);
        session = new Session();
    }

    // EVENT: triggered when the user clicks "Login" in the credentials capture pane
    private void on_credentials_login(string url, string username, string password) {
        if (has_error() || cancelled)
            return;
        
        do_network_login(url, username, password);
    }

    // EVENT:  triggered when an error occurs in the login transaction
    private void on_login_network_error(RESTTransaction bad_txn, PublishingError err) {
        bad_txn.completed.disconnect(on_login_network_complete);
        bad_txn.network_error.disconnect(on_login_network_error);

        if (has_error() || cancelled)
            return;
        if (session.is_authenticated()) // ignore these events if the session is already auth'd
            return;

        do_show_configure_capture_pane(GalleryConfigurePane.Mode.FAILED_RETRY);
    }
    

    // Helper method: retrieve internal name for the newly created diretory
    private string extract_new_created_album_name(RESTTransaction txn) {
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

    // EVENT: triggered when the network transaction that fetches the authentication token for
    //        the login account is completed successfully
    private void on_login_network_complete(RESTTransaction txn) {
        string auth_token;
        string cookie;
        
        txn.completed.disconnect(on_login_network_complete);
        txn.network_error.disconnect(on_login_network_error);

        int response = ((BaseGalleryTransaction)txn).check_gallery_response() ; 
        if (response == 999) {
            do_show_configure_capture_pane(GalleryConfigurePane.Mode.NOT_GALLERY_URL);
            return ;
        } else if (response != 0) {
            do_show_configure_capture_pane(GalleryConfigurePane.Mode.FAILED_RETRY);
            return ;
        }
        
        if (has_error() || cancelled)
            return;

        LoginTransaction login_txn = (LoginTransaction) txn;
        
        auth_token = login_txn.find_auth_token();
        cookie = login_txn.get_cookie_from_transaction();
        session.authenticate(login_txn.get_gallery_url(), login_txn.get_username(), login_txn.get_password(), auth_token, cookie);
        do_fetch_account_information();
    }
    
    public override string get_name() {
        return SERVICE_NAME ;
    }
    
    public override void cancel_interaction() {
        session.stop_transactions();
    }

    public override void start_interaction() {
        get_host().set_standard_window_mode();

        if (!session.is_authenticated()) {
            do_show_service_welcome_pane();
        } else {
            //do_show_service_welcome_pane();
            do_network_login(session.get_gallery_url(), session.get_username(), session.get_password());
        }
    }
    
    // EVENT: triggered when the batch uploader reports that at least one of the network
    //        transactions encapsulating uploads has completed successfully
    private void on_upload_complete(BatchUploader uploader, int num_published) {
        uploader.upload_complete.disconnect(on_upload_complete);
        uploader.upload_error.disconnect(on_upload_error);
        uploader.status_updated.disconnect(progress_pane.set_status);
        
        // TODO: add a descriptive, translatable error message string here
        if (num_published == 0)
            post_error(new PublishingError.LOCAL_FILE_ERROR(""));

        if (has_error() || cancelled)
            return;

        do_show_success_pane();
    }

    // ACTION: display the success pane in the publishing dialog
    private void do_show_success_pane() {
        get_host().unlock_service();
        get_host().set_close_button_mode();

        get_host().install_pane(new SuccessPane(MediaType.PHOTO));
    }

    // EVENT: triggered when the batch uploader reports that at least one of the network
    //        transactions encapsulating uploads has caused a network error
    private void on_upload_error(BatchUploader uploader, PublishingError err) {
        uploader.upload_complete.disconnect(on_upload_complete);
        uploader.upload_error.disconnect(on_upload_error);
        uploader.status_updated.disconnect(progress_pane.set_status);

        if (has_error() || cancelled)
            return;

        post_error(err);
    }

    // ACTION: display the service welcome pane in the publishing dialog
    private void do_show_service_welcome_pane() {
        debug("Gallery.Interactor.do_show_login_welcome_pane( ): ACTION: installing login welcome pane");
        
        LoginWelcomePane service_welcome_pane = new LoginWelcomePane(SERVICE_WELCOME_MESSAGE);
        service_welcome_pane.login_requested.connect(on_service_welcome_login);

        get_host().unlock_service();
        get_host().set_cancel_button_mode();

        get_host().install_pane(service_welcome_pane);
    }

    // EVENT: triggered when the network transaction that fetches the user's account information
    //        is completed successfully
    private void on_initial_album_fetch_complete(RESTTransaction txn) {
        txn.completed.disconnect(on_initial_album_fetch_complete);
        txn.network_error.disconnect(on_initial_album_fetch_error);
        if (has_error() || cancelled)
            return;

        do_parse_and_display_account_information((AlbumDirectoryTransaction) txn);
    }
    
    // ACTION: run a REST transaction over the network to create a new album with the parameters
    //         specified in 'parameters'. Display a wait pane with an info message in the
    //         publishing dialog while the transaction is running. This action should only
    //         occur if 'parameters' describes a publish-to-new-album operation.
    private void do_create_album(PublishingParameters parameters) {
        assert(parameters.is_to_new_album());

        get_host().install_pane(new StaticMessagePane(_("Creating album...")));

        get_host().lock_service();
        get_host().set_cancel_button_mode();

        AlbumCreationTransaction creation_trans = new AlbumCreationTransaction(session, session.get_gallery_url(),
            parameters);
        creation_trans.network_error.connect(on_album_creation_error);
        creation_trans.completed.connect(on_album_creation_complete);
        try{
            creation_trans.execute();
        } catch (PublishingError err) {
            post_error(err);
        }
    }
    
    // ACTION: run a REST transaction over the network to upload the user's photos to the remote
    //         endpoint. Display a progress pane while the transaction is running.
    private void do_upload() {
        progress_pane = new ProgressPane();
        get_host().install_pane(progress_pane);

        get_host().lock_service();
        get_host().set_cancel_button_mode();

        Photo[] photos = get_host().get_photos();
        uploader = new Uploader(session, parameters, photos);

        uploader.upload_complete.connect(on_upload_complete);
        uploader.upload_error.connect(on_upload_error);
        uploader.status_updated.connect(progress_pane.set_status);

        uploader.upload();
    }
    
    // ACTION: the response body of 'transaction' is an txt document that describes the user's
    //         Albums (e.g. the names of the user's albums ). Parse the response body of 
    //         'transaction' and display the publishing options pane with its widgets 
    //          populated such that they reflect the user's account info
    private void do_parse_and_display_account_information(AlbumDirectoryTransaction transaction) {
        string response_doc;
        
        // TODO: add try catch
        response_doc = transaction.get_response();
        
        albums = extract_gallery_albums(response_doc);


        do_show_publishing_options_pane();
    }
    
    // EVENT: triggered when the user clicks "Logout" in the publishing options pane
    private void on_publishing_options_logout() {
        if (has_error() || cancelled)
            return;

        session.deauthenticate();

        do_show_service_welcome_pane();
    }
    
    // EVENT: triggered when the user clicks "Publish" in the publishing options pane
    private void on_publishing_options_publish(PublishingParameters parameters) {
        if (has_error() || cancelled)
            return;
        
        this.parameters = parameters;

        if (parameters.is_to_new_album()) { 
            do_create_album(parameters);
        } else {
            do_upload();
        }
        
    }
    
    // ACTION: display the publishing options pane in the publishing dialog
    private void do_show_publishing_options_pane() {
        PublishingOptionsPane opts_pane = new PublishingOptionsPane(this, albums);
        opts_pane.publish.connect(on_publishing_options_publish);
        opts_pane.logout.connect(on_publishing_options_logout);
        get_host().install_pane(opts_pane);

        get_host().unlock_service();
        get_host().set_cancel_button_mode();
    }
    
    internal Session get_session() {
        return session;
    }
        
    // EVENT: triggered when the network transaction that fetches the user's account information
    //        fails
    private void on_initial_album_fetch_error(RESTTransaction bad_txn, PublishingError err) {
        bad_txn.completed.disconnect(on_initial_album_fetch_complete);
        bad_txn.network_error.disconnect(on_initial_album_fetch_error);

        if (has_error() || cancelled)
            return;

        if (bad_txn.get_status_code() == 403) {
            // if we get a 403 error (authentication failed) then we need to return to the login
            // screen because the user's auth token is no longer valid and he or she needs to
            // login again to obtain a new one
            session.deauthenticate();
            do_show_configure_capture_pane(GalleryConfigurePane.Mode.INTRO);
        } else {
            post_error(err);
        }
    }      
    
    // EVENT: triggered when the network transaction that creates a new album is completed
    //        successfully. This event should occur only when the user is publishing to a
    //        new album.
    private void on_album_creation_complete(RESTTransaction txn) {
        txn.completed.disconnect(on_album_creation_complete);
        txn.network_error.disconnect(on_album_creation_error);

        if (has_error() || cancelled)
            return;
        parameters.convert(extract_new_created_album_name(txn));
        do_upload();
    }

    // EVENT: triggered when the network transaction that creates a new album fails
    private void on_album_creation_error(RESTTransaction bad_txn, PublishingError err) {
        bad_txn.completed.disconnect(on_album_creation_complete);
        bad_txn.network_error.disconnect(on_album_creation_error);

        if (has_error() || cancelled)
            return;

        post_error(err);
    }
    
    // ACTION: run a REST transaction over the network to fetch the user's account information
    //         (e.g. the names of the user's albums and their corresponding REST URLs). While
    //         the network transaction is running, display a wait pane with an info message in
    //         the publishing dialog.
    private void do_fetch_account_information() {
        get_host().install_pane(new AccountFetchWaitPane());

        get_host().lock_service();
        get_host().set_cancel_button_mode();
        AlbumDirectoryTransaction directory_trans =
            new AlbumDirectoryTransaction(session, session.get_gallery_url() );
        directory_trans.network_error.connect(on_initial_album_fetch_error);
        directory_trans.completed.connect(on_initial_album_fetch_complete);
        try {
            directory_trans.execute();
        } catch (PublishingError err) {
            post_error(err);
        }
    }
    
    // EVENT: triggered when the user clicks "Login" in the service welcome pane
    private void on_service_welcome_login() {
        if (has_error() /*|| cancelled*/)
            return;

        do_show_configure_capture_pane(GalleryConfigurePane.Mode.INTRO);
    }
       
    // ACTION: given a username and password, run a REST transaction over the network to
    //         log a user into the Gallery Web Albums service
    private void do_network_login(string gallery_url, string username, string password) {
        get_host().install_pane(new LoginWaitPane());

        get_host().lock_service();
        get_host().set_cancel_button_mode();

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
        } catch (PublishingError err) {
            post_error(err);
        }
    }

    // EVENT: triggered when the user clicks the "Go Back" button in the credentials capture pane
    private void on_credentials_go_back() {
        // ignore all events if the user has cancelled or we have and error situation
        if (has_error() || cancelled)
            return;

        do_show_service_welcome_pane();
    }
    
    // ACTION: display the credentials capture pane in the publishing dialog; the credentials
    //         capture pane can be displayed in different "modes" that display different
    //         messages to the user
    private void do_show_configure_capture_pane(GalleryConfigurePane.Mode mode) {
        GalleryConfigurePane creds_pane = new GalleryConfigurePane(this, mode);
        creds_pane.go_back.connect(on_credentials_go_back);
        creds_pane.login.connect(on_credentials_login);

        get_host().unlock_service();
        get_host().set_cancel_button_mode();

        get_host().install_pane(creds_pane);
    }
    
    internal new PublishingDialog get_host() {
        return base.get_host();
    }
}

private class BaseGalleryTransaction : RESTTransaction {
    public BaseGalleryTransaction(Session session, string endpoint_url) {
        base.with_endpoint_url(session, endpoint_url, HttpMethod.POST);
        
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
        string? cookie = this.get_message().response_headers.get("Set-Cookie");
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

private class AuthenticatedTransaction : BaseGalleryTransaction {
    public AuthenticatedTransaction(Session session, string endpoint_url) {
        base(session, endpoint_url);

        add_argument("g2_authToken", session.get_auth_token());
        add_header("Cookie", session.get_cookie());
    }
}

private class AlbumDirectoryTransaction : AuthenticatedTransaction {
    public AlbumDirectoryTransaction(Session session, string url) {
        base(session, url);
        add_argument("g2_form[cmd]", "fetch-albums-prune");
    }
}

private class PublishingOptionsPane : PublishingDialogPane {
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

    private Gtk.ComboBox existing_albums_combo;
    private Gtk.Entry new_album_dir_entry ;
    private Gtk.Entry new_album_title_entry ;
    private Gtk.RadioButton use_existing_radio;
    private Gtk.RadioButton create_new_radio;
    private Interactor interactor;
    private Album[] albums;
    private SizeDescription[] size_descriptions;
    private Gtk.Button publish_button;

    public signal void publish(PublishingParameters parameters);
    public signal void logout();

    public PublishingOptionsPane(Interactor interactor, Album[] albums) {
        this.interactor = interactor;
        this.albums = albums;
        size_descriptions = create_size_descriptions();

        Gtk.SeparatorToolItem top_pusher = new Gtk.SeparatorToolItem();
        top_pusher.set_draw(false);
        top_pusher.set_size_request(-1, 8);
        add(top_pusher);

        Gtk.Label login_identity_label =
            new Gtk.Label(_("You are logged into Gallery Web Albums as %s.").printf(
            interactor.get_session().get_username()));

        add(login_identity_label);

        Gtk.VBox vert_packer = new Gtk.VBox(false, 0);
        Gtk.SeparatorToolItem packer_top_padding = new Gtk.SeparatorToolItem();
        packer_top_padding.set_draw(false);
        packer_top_padding.set_size_request(-1, PACKER_VERTICAL_PADDING);

        Gtk.SeparatorToolItem identity_table_spacer = new Gtk.SeparatorToolItem();
        identity_table_spacer.set_draw(false);
        identity_table_spacer.set_size_request(-1, INTERSTITIAL_VERTICAL_SPACING);
        vert_packer.add(identity_table_spacer);

        Gtk.Table main_table = new Gtk.Table(5, 4, false);

        Gtk.Label parent_dir_label = new Gtk.Label(_("In the directory:"));
        parent_dir_label.set_alignment(0.0f, 0.5f);
        main_table.attach(parent_dir_label, 0, 1, 0, 1,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 4, 4);

        existing_albums_combo = new Gtk.ComboBox.text();
        existing_albums_combo.changed.connect(on_use_existing_albums_combo_update);
        Gtk.Alignment existing_albums_combo_frame = new Gtk.Alignment(0.0f, 0.5f, 0.0f, 0.0f);
        existing_albums_combo_frame.add(existing_albums_combo);
        main_table.attach(existing_albums_combo_frame, 1, 2, 0, 1,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 4, 4);

        use_existing_radio = new Gtk.RadioButton.with_mnemonic(null, _("you will _upload your medias "));
        use_existing_radio.clicked.connect(on_use_existing_radio_clicked);
        main_table.attach(use_existing_radio, 1, 2, 1, 2,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 4, 4);

        create_new_radio = new Gtk.RadioButton.with_mnemonic(use_existing_radio.get_group(),
            _("create a _new album to upload medias in:"));
        create_new_radio.clicked.connect(on_create_new_radio_clicked);
        main_table.attach(create_new_radio, 1, 2, 2, 3,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 4, 4);

        Gtk.Label new_dir_label = new Gtk.Label.with_mnemonic(_("_dir name:"));
        new_dir_label.set_alignment(0.0f, 0.5f);
        main_table.attach(new_dir_label, 1, 2, 3, 4,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 4, 4);
            
        new_album_dir_entry = new Gtk.Entry();
        new_album_dir_entry.changed.connect(on_new_album_entry_changed);
        main_table.attach(new_album_dir_entry, 2, 3, 3, 4,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 4, 4);
            
        new_dir_label.set_mnemonic_widget(new_album_dir_entry);

        Gtk.Label new_title_label = new Gtk.Label.with_mnemonic(_("_title name:"));
        new_title_label.set_alignment(0.0f, 0.5f);
        main_table.attach(new_title_label, 1, 2, 4, 5,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 4, 4);
            
        new_album_title_entry = new Gtk.Entry();
        new_album_title_entry.changed.connect(on_new_album_entry_changed);
        main_table.attach(new_album_title_entry, 2, 3, 4, 5,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 4, 4);
        
        new_title_label.set_mnemonic_widget(new_album_title_entry);
        
        Gtk.SeparatorToolItem album_size_spacer = new Gtk.SeparatorToolItem();
        album_size_spacer.set_draw(false);
        album_size_spacer.set_size_request(-1, INTERSTITIAL_VERTICAL_SPACING / 2);
        main_table.attach(album_size_spacer, 3, 4, 4, 5,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 4, 4);

        vert_packer.add(main_table);

        Gtk.SeparatorToolItem table_button_spacer = new Gtk.SeparatorToolItem();
        table_button_spacer.set_draw(false);
        table_button_spacer.set_size_request(-1, INTERSTITIAL_VERTICAL_SPACING);
        vert_packer.add(table_button_spacer);

        Gtk.HBox action_button_layouter = new Gtk.HBox(true, 0);

        Gtk.Button logout_button = new Gtk.Button.with_mnemonic(_("_Logout"));
        logout_button.clicked.connect(on_logout_clicked);
        logout_button.set_size_request(PublishingDialog.STANDARD_ACTION_BUTTON_WIDTH, -1);
        Gtk.Alignment logout_button_aligner = new Gtk.Alignment(0.5f, 0.5f, 0.0f, 0.0f);
        logout_button_aligner.add(logout_button);
        action_button_layouter.add(logout_button_aligner);
        Gtk.SeparatorToolItem button_spacer = new Gtk.SeparatorToolItem();
        button_spacer.set_draw(false);
        button_spacer.set_size_request(ACTION_BUTTON_SPACING, -1);
        action_button_layouter.add(button_spacer);
        publish_button = new Gtk.Button.with_mnemonic(_("_Publish"));
        publish_button.clicked.connect(on_publish_clicked);
        publish_button.set_size_request(PublishingDialog.STANDARD_ACTION_BUTTON_WIDTH, -1);
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
        if (create_new_radio.get_active()) {
            string new_album_dir = new_album_dir_entry.get_text();
            string new_album_title = new_album_title_entry.get_text();
            publish(new PublishingParameters.to_new_album(albums[existing_albums_combo.get_active()].name, 
                                                          new_album_dir.strip(), 
                                                          new_album_title.strip()));
        } else {
            string album_name = albums[existing_albums_combo.get_active()].name;
            publish(new PublishingParameters.to_existing_album(album_name));
        }
    }

    private void on_use_existing_radio_clicked() {
        new_album_dir_entry.set_sensitive(false);
        new_album_title_entry.set_sensitive(false);
        existing_albums_combo.grab_focus();
        update_publish_button_sensitivity();
    }

    private void on_use_existing_albums_combo_update() {
        update_publish_button_sensitivity();
    }
    private void on_create_new_radio_clicked() {
        new_album_dir_entry.set_sensitive(true);
        new_album_title_entry.set_sensitive(true);
        new_album_dir_entry.grab_focus();
        update_publish_button_sensitivity();
    }

    private void on_logout_clicked() {
        logout();
    }

    private void update_publish_button_sensitivity() {
        if (existing_albums_combo.get_active() == -1)
        {
            publish_button.set_sensitive(false);
            return;
        }
        if (create_new_radio.get_active()) {
            string new_album_dir = new_album_dir_entry.get_text();
            publish_button.set_sensitive(albums[existing_albums_combo.get_active()].perms.create_sub && (new_album_dir.strip() != ""));
        } else {
            publish_button.set_sensitive(albums[existing_albums_combo.get_active()].perms.add);
        }
    }

    private void on_new_album_entry_changed() {
        update_publish_button_sensitivity();
    }

    private SizeDescription[] create_size_descriptions() {
        SizeDescription[] result = new SizeDescription[0];

        result += SizeDescription(_("Small (640 x 480 pixels)"), 640);
        result += SizeDescription(_("Medium (1024 x 768 pixels)"), 1024);
        result += SizeDescription(_("Recommended (1600 x 1200 pixels)"), 1600);
        result += SizeDescription(_("Original Size"), ORIGINAL_SIZE);

        return result;
    }

    public override void installed() {
        int default_album_id = -1;
        for (int i = 0; i < albums.length; i++) {
            existing_albums_combo.append_text(albums[i].title);
            if (albums[i].title == DEFAULT_ALBUM_TITLE)
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
            } else {
                create_new_radio.set_active(true);
                existing_albums_combo.set_active(0);
                new_album_dir_entry.grab_focus();
                new_album_dir_entry.set_text(DEFAULT_ALBUM_DIR);
                new_album_title_entry.set_text(DEFAULT_ALBUM_TITLE);
            }
        }
        update_publish_button_sensitivity();
    }
}


private class Session : RESTSession {
    private string password;
    private string username;
    private string url;
    private string auth_token;
    private string cookie;
    
    public Session() {
        base(""); 
        if (has_persistent_state())
            load_persistent_state();
    }

    private bool has_persistent_state() {
        Config config = Config.get_instance();

        return ((config.get_publishing_string(CONFIG_NAME, "username") != null) &&
                (config.get_publishing_string(CONFIG_NAME, "password") != null) &&
                (config.get_publishing_string(CONFIG_NAME, "url") != null));
    }
    
    private void save_persistent_state() {
        Config config = Config.get_instance();

        config.set_publishing_string(CONFIG_NAME, "url", url);
        config.set_publishing_string(CONFIG_NAME, "username", username);
        config.set_publishing_string(CONFIG_NAME, "password", password);
    }

    private void load_persistent_state() {
        Config config = Config.get_instance();

        url = config.get_publishing_string(CONFIG_NAME, "url");
        username = config.get_publishing_string(CONFIG_NAME, "username");
        password = config.get_publishing_string(CONFIG_NAME, "password");
    }
    
    private void clear_persistent_state() {
        Config config = Config.get_instance();

        config.set_publishing_string(CONFIG_NAME, "url", "");
        config.set_publishing_string(CONFIG_NAME, "username", "");
        config.set_publishing_string(CONFIG_NAME, "password", "");
    }

    public bool is_authenticated() {
        return (password != null);
    }

    public void authenticate(string gallery_url, string username, string password, string auth_token, string cookie) {
        this.url = gallery_url;
        this.password = password;
        this.username = username;
        this.auth_token = auth_token;
        this.cookie = cookie ;
        
        save_persistent_state();
    }
    
    public void deauthenticate() {
        url = null;
        password = null;
        username = null;
        cookie = null;
        auth_token = null;
        
        clear_persistent_state();
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

private class Uploader : BatchUploader {
    private Session session;
    private PublishingParameters parameters;

    public Uploader(Session session, PublishingParameters params, Photo[] photos) {
        base(photos);

        this.session = session;
        this.parameters = params;
    }

    protected override bool prepare_file(BatchUploader.TemporaryFileDescriptor file) {
        Scaling scaling = Scaling.for_original();
        
        try {
            if (file.media is Photo) {
                ((Photo) file.media).export(file.temp_file, scaling, Jpeg.Quality.MAXIMUM,
                    PhotoFileFormat.JFIF);
            }
        } catch (Error e) {
            return false;
        }
        
        return true;
    }

    protected override RESTTransaction create_transaction_for_file(
        BatchUploader.TemporaryFileDescriptor file) {
        return new GalleryUploadTransaction(session, parameters,  file.temp_file.get_path(), file.media);
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

private class GalleryUploadTransaction : MediaUploadTransaction {
    private Session session_copy = null;
    private string source_file;
    private MediaSource media;
    private GLib.HashTable<string, string> binary_disposition_table = null;
        
    public GalleryUploadTransaction(Session session, PublishingParameters params, 
                                       string source_file, MediaSource media_source) {
        base.with_endpoint_url(session, session.get_gallery_url(), source_file, media_source);
        assert(session.is_authenticated());
        
        this.session_copy = session;
        this.source_file = source_file;
        this.media = media_source;
        
        debug("GalleryUploadTransaction upload file %s", media.get_name());
        
        add_argument("g2_form[cmd]", "add-item");
        add_argument("g2_form[protocol_version]", "2.10");
        add_argument("g2_form[set_albumName]", params.album_name);
        // TODO: add_argument("g2_form[caption]", "");
        add_argument("g2_form[userfile_name]", media.get_name());
        add_argument("g2_form[force_filename]", media.get_name());
        add_argument("g2_form[auto_rotate]", "yes");
        add_argument("g2_authToken", session.get_auth_token());
        add_argument("g2_controller", "remote.GalleryRemote");
        
        GLib.HashTable<string, string> disposition_table =
            new GLib.HashTable<string, string>(GLib.str_hash, GLib.str_equal);
        disposition_table.insert("filename", media.get_name());
        disposition_table.insert("name", "g2_userfile");
        set_binary_disposition_table(disposition_table);
    }
    
    protected new void set_binary_disposition_table(GLib.HashTable<string, string> new_disp_table) {
        binary_disposition_table = new_disp_table;
    }
    
    // Need to copy and paste this method to add the cookie header to the sent message.
    public override void execute() {

        RESTArgument[] request_arguments = get_arguments();
        assert(request_arguments.length > 0);

        // create the multipart request container
        Soup.Multipart message_parts = new Soup.Multipart("multipart/form-data");

        // attach each REST argument as its own multipart formdata part
        foreach (RESTArgument arg in request_arguments)
            message_parts.append_form_string(arg.key, arg.value);

        // attempt to read the binary image data from disk
        string photo_data;
        size_t data_length;
        try {
            FileUtils.get_contents(source_file, out photo_data, out data_length);
        } catch (FileError e) {
            error("PhotoUploadTransaction: couldn't read data from file '%s'", source_file);
        }

        // get the sequence number of the part that will soon become the binary image data
        // part
        int image_part_num = message_parts.get_length();

        // bind the binary image data read from disk into a Soup.Buffer object so that we
        // can attach it to the multipart request, then actaully append the buffer
        // to the multipart request. Then, set the MIME type for this part.
        Soup.Buffer bindable_data = new Soup.Buffer(Soup.MemoryUse.COPY, photo_data, data_length);
        message_parts.append_form_file("", source_file, "image/jpeg", bindable_data);

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

private class GalleryConfigurePane : PublishingDialogPane {
    public enum Mode {
        INTRO,
        FAILED_RETRY,
        NOT_GALLERY_URL
    }
    private const string INTRO_MESSAGE = _("Enter the Gallery name and address and login and password associated with this Gallery.");
    private const string FAILED_RETRY_MESSAGE = _("Retry message");
    private const string NOT_GALLERY_URL_MESSAGE = _("Not a gallery url");
    
    private const int UNIFORM_ACTION_BUTTON_WIDTH = 102;

    private Gtk.Entry gallery_url_entry;
    private Gtk.Entry uname_entry;
    private Gtk.Entry password_entry;
    private Gtk.Button login_button;
    private Gtk.Button go_back_button;
    private weak Interactor interactor;

    public signal void go_back();
    public signal void login(string gallery_url, string uname, string password);

    public GalleryConfigurePane(Interactor interactor, Mode mode = Mode.INTRO) {
        this.interactor = interactor;

        Gtk.SeparatorToolItem top_space = new Gtk.SeparatorToolItem();
        top_space.set_draw(false);
        Gtk.SeparatorToolItem bottom_space = new Gtk.SeparatorToolItem();
        bottom_space.set_draw(false);
        add(top_space);
        top_space.set_size_request(-1, 40);

        Gtk.Label intro_message_label = new Gtk.Label("");
        intro_message_label.set_line_wrap(true);
        add(intro_message_label);
        intro_message_label.set_size_request(PublishingDialog.STANDARD_CONTENT_LABEL_WIDTH, -1);
        intro_message_label.set_alignment(0.5f, 0.0f);
        switch (mode) {
            case Mode.INTRO:
                intro_message_label.set_text(INTRO_MESSAGE);
            break;

            case Mode.FAILED_RETRY:
                intro_message_label.set_markup("<b>%s</b>\n\n%s".printf(_(
                    "Unrecognized User"), FAILED_RETRY_MESSAGE));
            break;

            case Mode.NOT_GALLERY_URL:
                intro_message_label.set_markup("<b>%s</b>\n\n%s".printf(_("This is not a Gallery Url"),
                    NOT_GALLERY_URL_MESSAGE));
                Gtk.SeparatorToolItem long_message_space = new Gtk.SeparatorToolItem();
                long_message_space.set_draw(false);
                add(long_message_space);
                long_message_space.set_size_request(-1, 40);
            break;
        }

        Gtk.Alignment entry_widgets_table_aligner = new Gtk.Alignment(0.5f, 0.5f, 0.0f, 0.0f);
        Gtk.Table entry_widgets_table = new Gtk.Table(4,2, false);
        Gtk.Label gallery_url_entry_label = new Gtk.Label.with_mnemonic(_("_URL:"));
        gallery_url_entry_label.set_alignment(0.0f, 0.5f);
        Gtk.Label uname_entry_label = new Gtk.Label.with_mnemonic(_("_Login:"));
        uname_entry_label.set_alignment(0.0f, 0.5f);
        Gtk.Label password_entry_label = new Gtk.Label.with_mnemonic(_("_Password:"));
        password_entry_label.set_alignment(0.0f, 0.5f);
        gallery_url_entry = new Gtk.Entry();
        gallery_url_entry.changed.connect(on_uname_gallery_url_changed);
        uname_entry = new Gtk.Entry();
        uname_entry.changed.connect(on_uname_gallery_url_changed);
        password_entry = new Gtk.Entry();
        password_entry.set_visibility(false);
        entry_widgets_table.attach(gallery_url_entry_label, 0, 1, 0, 1,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 6, 6);
        entry_widgets_table.attach(uname_entry_label, 0, 1, 1, 2,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 6, 6);
        entry_widgets_table.attach(password_entry_label, 0, 1, 2, 3,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 6, 6);
        entry_widgets_table.attach(gallery_url_entry, 1, 2, 0, 1,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 6, 6);
        entry_widgets_table.attach(uname_entry, 1, 2, 1, 2,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 6, 6);
        entry_widgets_table.attach(password_entry, 1, 2, 2, 3,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 6, 6);
        go_back_button = new Gtk.Button.with_mnemonic(_("Go _Back"));
        go_back_button.clicked.connect(on_go_back_button_clicked);
        Gtk.Alignment go_back_button_aligner = new Gtk.Alignment(0.0f, 0.5f, 0.0f, 0.0f);
        go_back_button_aligner.add(go_back_button);
        go_back_button.set_size_request(UNIFORM_ACTION_BUTTON_WIDTH, -1);
        login_button = new Gtk.Button.with_mnemonic(_("_Login"));
        login_button.clicked.connect(on_login_button_clicked);
        login_button.set_sensitive(false);
        Gtk.Alignment login_button_aligner = new Gtk.Alignment(1.0f, 0.5f, 0.0f, 0.0f);
        login_button_aligner.add(login_button);
        login_button.set_size_request(UNIFORM_ACTION_BUTTON_WIDTH, -1);
        entry_widgets_table.attach(go_back_button_aligner, 0, 1, 3, 4,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 6, 40);
        entry_widgets_table.attach(login_button_aligner, 1, 2, 3, 4,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL,
            Gtk.AttachOptions.EXPAND | Gtk.AttachOptions.FILL, 6, 40);
        entry_widgets_table_aligner.add(entry_widgets_table);
        add(entry_widgets_table_aligner);

        uname_entry_label.set_mnemonic_widget(uname_entry);
        password_entry_label.set_mnemonic_widget(password_entry);

        add(bottom_space);
        bottom_space.set_size_request(-1, 40);
    }

    private void on_login_button_clicked() {
        login(gallery_url_entry.get_text(), uname_entry.get_text(), password_entry.get_text());
    }

    private void on_go_back_button_clicked() {
        go_back();
    }
    
    private void on_uname_gallery_url_changed() {
        login_button.set_sensitive((uname_entry.get_text() != "") 
                                 &&(gallery_url_entry.get_text() != ""));
    }

    public override void installed() {
        uname_entry.grab_focus();
        password_entry.set_activates_default(true);
        login_button.can_default = true;
        interactor.get_host().set_default(login_button);
    }
}

}

#endif

