/* Copyright 2009-2011 Yorba Foundation
 *
 * This software is licensed under the GNU Lesser General Public License
 * (version 2.1 or later).  See the COPYING file in this distribution. 
 */

extern Soup.Message soup_form_request_new_from_multipart(string uri, Soup.Multipart multipart);
extern void qsort(void *p, size_t num, size_t size, GLib.CompareFunc func);

namespace Publishing.RESTSupport {

public abstract class Session {
    private string? endpoint_url = null;
    private Soup.Session soup_session = null;
    private bool transactions_stopped = false;
    
    public signal void wire_message_unqueued(Soup.Message message);
    public signal void authenticated();
    public signal void authentication_failed(Spit.Publishing.PublishingError err);

    public Session(string? endpoint_url = null) {
        this.endpoint_url = endpoint_url;
        soup_session = new Soup.SessionAsync();
    }
    
    protected void notify_wire_message_unqueued(Soup.Message message) {
        wire_message_unqueued(message);
    }
    
    protected void notify_authenticated() {
        authenticated();
    }
    
    protected void notify_authentication_failed(Spit.Publishing.PublishingError err) {
        authentication_failed(err);
    }

    public abstract bool is_authenticated();
    
    public string? get_endpoint_url() {
        return endpoint_url;
    }
    
    public void stop_transactions() {
        transactions_stopped = true;
        soup_session.abort();
    }
    
    public bool are_transactions_stopped() {
        return transactions_stopped;
    }
    
    public void send_wire_message(Soup.Message message) {
        if (are_transactions_stopped())
            return;

        soup_session.request_unqueued.connect(notify_wire_message_unqueued);
        soup_session.send_message(message);
        
        soup_session.request_unqueued.disconnect(notify_wire_message_unqueued);
    }
}

public enum HttpMethod {
    GET,
    POST,
    PUT;

    public string to_string() {
        switch (this) {
            case HttpMethod.GET:
                return "GET";

            case HttpMethod.PUT:
                return "PUT";

            case HttpMethod.POST:
                return "POST";

            default:
                error("unrecognized HTTP method enumeration value");
        }
    }

    public static HttpMethod from_string(string str) {
        if (str == "GET") {
            return HttpMethod.GET;
        } else if (str == "PUT") {
            return HttpMethod.PUT;
        } else if (str == "POST") {
            return HttpMethod.POST;
        } else {
            error("unrecognized HTTP method name: %s", str);
        }
    }
}

public struct Argument {
    public string key;
    public string value;

    public Argument(string key, string value) {
        this.key = key;
        this.value = value;
    }

    public static int compare(void* p1, void* p2) {
        Argument* arg1 = (Argument*) p1;
        Argument* arg2 = (Argument*) p2;

        return strcmp(arg1->key, arg2->key);
    }
}

public class Transaction {
    private Argument[] arguments;
    private bool is_executed = false;
    private weak Session parent_session = null;
    private Soup.Message message = null;
    private int bytes_written = 0;
    private Spit.Publishing.PublishingError? err = null;
    private string? endpoint_url = null;
    private bool use_custom_payload;
    
    public signal void chunk_transmitted(int bytes_written_so_far, int total_bytes);
    public signal void network_error(Spit.Publishing.PublishingError err);
    public signal void completed();
    
    public Transaction(Session parent_session, HttpMethod method = HttpMethod.POST) {
        // if our creator doesn't specify an endpoint url by using the Transaction.with_endpoint_url
        // constructor, then our parent session must have a non-null endpoint url
        assert(parent_session.get_endpoint_url() != null);
        
        this.parent_session = parent_session;

        message = new Soup.Message(method.to_string(), parent_session.get_endpoint_url());
        message.wrote_body_data.connect(on_wrote_body_data);
    }

    public Transaction.with_endpoint_url(Session parent_session, string endpoint_url,
        HttpMethod method = HttpMethod.POST) {
        this.parent_session = parent_session;
        this.endpoint_url = endpoint_url;
        message = new Soup.Message(method.to_string(), endpoint_url);
    }

    private void on_wrote_body_data(Soup.Buffer written_data) {
        bytes_written += (int) written_data.length;
        chunk_transmitted(bytes_written, (int) message.request_body.length);
    }

    private void on_message_unqueued(Soup.Message message) {
        if (this.message != message)
            return;

        try {
            check_response(message);
        } catch (Spit.Publishing.PublishingError err) {
            warning("Publishing error: %s", err.message);
            warning("response validation failed. bad response = '%s'.", get_response());
            this.err = err;
        }
    }

    protected void check_response(Soup.Message message) throws Spit.Publishing.PublishingError {
        switch (message.status_code) {
            case Soup.KnownStatusCode.OK:
            case Soup.KnownStatusCode.CREATED: // HTTP code 201 (CREATED) signals that a new
                                               // resource was created in response to a PUT or POST
            break;
            
            case Soup.KnownStatusCode.CANT_RESOLVE:
            case Soup.KnownStatusCode.CANT_RESOLVE_PROXY:
                throw new Spit.Publishing.PublishingError.NO_ANSWER("Unable to resolve %s (error code %u)",
                    get_endpoint_url(), message.status_code);
            
            case Soup.KnownStatusCode.CANT_CONNECT:
            case Soup.KnownStatusCode.CANT_CONNECT_PROXY:
                throw new Spit.Publishing.PublishingError.NO_ANSWER("Unable to connect to %s (error code %u)",
                    get_endpoint_url(), message.status_code);
            
            default:
                // status codes below 100 are used by Soup, 100 and above are defined HTTP codes
                if (message.status_code >= 100) {
                    throw new Spit.Publishing.PublishingError.NO_ANSWER("Service %s returned HTTP status code %u %s",
                        get_endpoint_url(), message.status_code, message.reason_phrase);
                } else {
                    throw new Spit.Publishing.PublishingError.NO_ANSWER("Failure communicating with %s (error code %u)",
                        get_endpoint_url(), message.status_code);
                }
        }
        
        // All valid communication involves body data in the response
        if (message.response_body.data == null || message.response_body.data.length == 0)
            throw new Spit.Publishing.PublishingError.MALFORMED_RESPONSE("No response data from %s",
                get_endpoint_url());
    }

    protected Argument[] get_arguments() {
        return arguments;
    }
    
    protected Argument[] get_sorted_arguments() {
        Argument[] sorted_array = new Argument[0];

        foreach (Argument arg in arguments)
            sorted_array += arg;

        qsort(sorted_array, sorted_array.length, sizeof(Argument),
            (CompareFunc) Argument.compare);

        return sorted_array;
    }
    
    protected void set_is_executed(bool is_executed) {
        this.is_executed = is_executed;
    }

    protected void send() throws Spit.Publishing.PublishingError {
        parent_session.wire_message_unqueued.connect(on_message_unqueued);
        message.wrote_body_data.connect(on_wrote_body_data);
        parent_session.send_wire_message(message);
        
        parent_session.wire_message_unqueued.disconnect(on_message_unqueued);
        message.wrote_body_data.disconnect(on_wrote_body_data);
        
        if (err != null)
            network_error(err);
        else
            completed();
        
        if (err != null)
            throw err;
     }

    protected HttpMethod get_method() {
        return HttpMethod.from_string(message.method);
    }

    protected void add_header(string key, string value) {
        message.request_headers.append(key, value);
    }
    
    // set custom_payload to null to have this transaction send the default payload of
    // key-value pairs appended through add_argument(...) (this is how most REST requests work).
    // To send a payload other than traditional key-value pairs (such as an XML document or a JPEG
    // image) to the endpoint, set the custom_payload parameter to a non-null value. If the
    // custom_payload you specify is text data, then it's null terminated, and its length is just 
    // custom_payload.length, so you don't have to pass in a payload_length parameter in this case.
    // If, however, custom_payload is binary data (such as a JEPG), then the caller must set
    // payload_length to the byte length of the custom_payload buffer
    protected void set_custom_payload(string? custom_payload, string payload_content_type,
        ulong payload_length = 0) {
        assert (get_method() != HttpMethod.GET); // GET messages don't have payloads

        if (custom_payload == null) {
            use_custom_payload = false;
            return;
        }
        
        ulong length = (payload_length > 0) ? payload_length : custom_payload.length;
        message.set_request(payload_content_type, Soup.MemoryUse.COPY, custom_payload.data[0:length]);

        use_custom_payload = true;
    }
    
    // When writing a specialized transaction subclass you should rarely need to
    // call this method. In general, it's better to leave the underlying Soup message
    // alone and let the Transaction class manage it for you. You should only need
    // to install a new message if your subclass has radically different behavior from
    // normal Transactions -- like multipart encoding.
    protected void set_message(Soup.Message message) {
        this.message = message;
    }
    
    public bool get_is_executed() {
        return is_executed;
    }

    public uint get_status_code() {
        assert(get_is_executed());
        return message.status_code;
    }

    public virtual void execute() throws Spit.Publishing.PublishingError {
        // if a custom payload is being used, we don't need to peform the tasks that are necessary
        // to prepare a traditional key-value pair REST request; Instead (since we don't
        // know anything about the custom payload), we just put it on the wire and return
        if (use_custom_payload) {
            is_executed = true;
            send();

            return;
         }
         
        //  REST POST requests must transmit at least one argument
        if (get_method() == HttpMethod.POST)
            assert(arguments.length > 0);

        // concatenate the REST arguments array into an HTTP formdata string
        string formdata_string = "";
        foreach (Argument arg in arguments) {
            formdata_string = formdata_string + ("%s=%s&".printf(Soup.URI.encode(arg.key, "&"),
                Soup.URI.encode(arg.value, "&+")));
        }

        // for GET requests with arguments, append the formdata string to the endpoint url after a
        // query divider ('?') -- but make sure to save the old (caller-specified) endpoint URL
        // and restore it after the GET so that the underlying Soup message remains consistent
        string old_url = null;
        string url_with_query = null;
        if (get_method() == HttpMethod.GET && arguments.length > 0) {
            old_url = message.get_uri().to_string(false);
            url_with_query = get_endpoint_url() + "?" + formdata_string;
            message.set_uri(new Soup.URI(url_with_query));
        }

        message.set_request("application/x-www-form-urlencoded", Soup.MemoryUse.COPY,
            formdata_string.data);
        is_executed = true;
        try {
            send();
        } finally {
            // if old_url is non-null, then restore it
            if (old_url != null)
                message.set_uri(new Soup.URI(old_url));
        }
    }

    public string get_response() {
        assert(get_is_executed());
        return (string) message.response_body.data;
    }
    
    public string get_header_response(string selection) {
        assert(get_is_executed());
        return (string) message.response_headers.get(selection);
    }
    public void add_argument(string name, string value) {
        arguments += Argument(name, value);
    }
    
    public string? get_endpoint_url() {
        return (endpoint_url != null) ? endpoint_url : parent_session.get_endpoint_url();
    }
    
    public Session get_parent_session() {
        return parent_session;
    }
}

public class UploadTransaction : Transaction {
    private GLib.HashTable<string, string> binary_disposition_table = null;
    private Spit.Publishing.Publishable publishable = null;
    private string mime_type;

    public UploadTransaction(Session session, Spit.Publishing.Publishable publishable) {
        base (session);
        this.publishable = publishable;
        this.mime_type = media_type_to_mime_type(publishable.get_media_type());

        binary_disposition_table = create_default_binary_disposition_table();
    }
    
    public UploadTransaction.with_endpoint_url(Session session,
        Spit.Publishing.Publishable publishable, string endpoint_url) {
        base.with_endpoint_url(session, endpoint_url);
        this.publishable = publishable;
        this.mime_type = media_type_to_mime_type(publishable.get_media_type());

        binary_disposition_table = create_default_binary_disposition_table();
    }
    
    private static string media_type_to_mime_type(Spit.Publishing.Publisher.MediaType media_type) {
        if (media_type == Spit.Publishing.Publisher.MediaType.PHOTO)
            return "image/jpeg";
        else if (media_type == Spit.Publishing.Publisher.MediaType.VIDEO)
            return "video/mpeg";
        else
            error("UploadTransaction: unknown media type %s.", media_type.to_string());
    }

    private GLib.HashTable<string, string> create_default_binary_disposition_table() {
        GLib.HashTable<string, string> result =
            new GLib.HashTable<string, string>(GLib.str_hash, GLib.str_equal);

        result.insert("filename", Soup.URI.encode(publishable.get_serialized_file().get_basename(),
            null));

        return result;
    }

    protected void set_binary_disposition_table(GLib.HashTable<string, string> new_disp_table) {
        binary_disposition_table = new_disp_table;
    }

    public override void execute() throws Spit.Publishing.PublishingError {
        Argument[] request_arguments = get_arguments();
        assert(request_arguments.length > 0);

        Soup.Multipart message_parts = new Soup.Multipart("multipart/form-data");

        foreach (Argument arg in request_arguments)
            message_parts.append_form_string(arg.key, arg.value);

        string payload;
        size_t payload_length;
        try {
            FileUtils.get_contents(publishable.get_serialized_file().get_path(), out payload,
                out payload_length);
        } catch (FileError e) {
            throw new Spit.Publishing.PublishingError.LOCAL_FILE_ERROR(
                _("A temporary file needed for publishing is unavailable"));
        }

        int payload_part_num = message_parts.get_length();

        Soup.Buffer bindable_data = new Soup.Buffer(Soup.MemoryUse.COPY, payload.data[0:payload_length]);
        message_parts.append_form_file("", publishable.get_serialized_file().get_path(), mime_type,
            bindable_data);

        unowned Soup.MessageHeaders image_part_header;
        unowned Soup.Buffer image_part_body;
        message_parts.get_part(payload_part_num, out image_part_header, out image_part_body);
        image_part_header.set_content_disposition("form-data", binary_disposition_table);

        Soup.Message outbound_message =
            soup_form_request_new_from_multipart(get_endpoint_url(), message_parts);
        set_message(outbound_message);
        
        set_is_executed(true);
        send();
    }
}


/* Encoding strings in XML decimal encoding is a relatively esoteric operation. Most web services
   prefer to have non-ASCII character entities encoded using "symbolic encoding," where common
   entities are encoded in short, symbolic names (e.g. "ñ" -> &ntilde;). Picasa Web Albums,
   however, doesn't like symbolic encoding, and instead wants non-ASCII entities encoded directly
   as their Unicode code point numbers (e.g. "ñ" -> &241;). */
public string decimal_entity_encode(string source) {
    StringBuilder encoded_str_builder = new StringBuilder();
    string current_char = source;
    while (true) {
        int current_char_value = (int) (current_char.get_char_validated());
        
        if (current_char_value < 1)
            break;
        else if (current_char_value < 128)
            encoded_str_builder.append_unichar(current_char.get_char_validated());
        else
            encoded_str_builder.append("&#%d;".printf(current_char_value));

        current_char = current_char.next_char();
    }
    
    return encoded_str_builder.str;
}

internal abstract class BatchUploader {
    private int current_file = 0;
    private Spit.Publishing.Publishable[] publishables = null;
    private Session session = null;
	private Spit.Publishing.ProgressCallback? status_updated = null;

    public signal void upload_complete(int num_photos_published);
    public signal void upload_error(Spit.Publishing.PublishingError err);

    public BatchUploader(Session session, Spit.Publishing.Publishable[] publishables) {
        this.publishables = publishables;
        this.session = session;
    }

    private void send_files() {
        current_file = 0;
        bool stop = false;
        foreach (Spit.Publishing.Publishable publishable in publishables) {
            GLib.File? file = publishable.get_serialized_file();
            assert (file != null);

            double fraction_complete = ((double) current_file) / publishables.length;
                if (status_updated != null)
                    status_updated(current_file + 1, fraction_complete);

            Transaction txn = create_transaction(publishables[current_file]);
           
            txn.chunk_transmitted.connect(on_chunk_transmitted);
            
            try {
                txn.execute();
            } catch (Spit.Publishing.PublishingError err) {
                upload_error(err);
                stop = true;
            }
                
            txn.chunk_transmitted.disconnect(on_chunk_transmitted);           
            
            if (stop)
                break;
            
            current_file++;
        }
        
        if (!stop)
            upload_complete(current_file);
    }
    
    private void on_chunk_transmitted(int bytes_written_so_far, int total_bytes) {
        double file_span = 1.0 / publishables.length;
        double this_file_fraction_complete = ((double) bytes_written_so_far) / total_bytes;
        double fraction_complete = (current_file * file_span) + (this_file_fraction_complete *
            file_span);

		if (status_updated != null)
	        status_updated(current_file + 1, fraction_complete);
    }
    
    protected Session get_session() {
        return session;
    }
    
    protected Spit.Publishing.Publishable get_current_publishable() {
        return publishables[current_file];
    }
    
    protected abstract Transaction create_transaction(Spit.Publishing.Publishable publishable);
    
    public void upload(Spit.Publishing.ProgressCallback? status_updated = null) {
        this.status_updated = status_updated;

        if (publishables.length > 0)
           send_files();
    }
}

// Remove diacritics in a string, yielding ASCII.  If the given string is in
// a character set not based on Latin letters (e.g. Cyrillic), the result
// may be empty.
public string asciify_string(string s) {
    string t = s.normalize();  // default normalization yields a maximally decomposed form
    
    StringBuilder b = new StringBuilder();
    for (unowned string u = t; u.get_char() != 0 ; u = u.next_char()) {
        unichar c = u.get_char();
        if ((int) c < 128)
            b.append_unichar(c);
    }
    
    return b.str;
}

}

