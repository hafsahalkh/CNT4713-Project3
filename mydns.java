import java.net.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class mydns {

    // Resource Record class to store parsed RR data
    static class ResourceRecord {
        String name;
        int type;
        int rrClass;
        long ttl;
        int rdLength;
        byte[] rdata;
        String rdataString; // For display purposes

        ResourceRecord(String name, int type, int rrClass, long ttl, int rdLength, byte[] rdata) {
            this.name = name;
            this.type = type;
            this.rrClass = rrClass;
            this.ttl = ttl;
            this.rdLength = rdLength;
            this.rdata = rdata;
        }
    }

    // DNS Response class to store parsed response data
    static class DNSResponse {
        int id;
        int flags;
        int qdcount;
        int ancount;
        int nscount;
        int arcount;
        String qname;
        int qtype;
        int qclass;
        List<ResourceRecord> answers;
        List<ResourceRecord> authorities;
        List<ResourceRecord> additionals;

        DNSResponse() {
            answers = new ArrayList<>();
            authorities = new ArrayList<>();
            additionals = new ArrayList<>();
        }
    }

    // create DNS query message
    public static byte[] createQuery(int id, String domainName) {
        // Header section
        ByteBuffer query = ByteBuffer.allocate(1024);
        query.order(ByteOrder.BIG_ENDIAN);

        // Query header [RFC 4.1.1. Header section format]
        // 1 1 1 1 1 1
        // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // | ID |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |QR| Opcode |AA|TC|RD|RA| Z | RCODE |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // | QDCOUNT |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // | ANCOUNT |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // | NSCOUNT |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // | ARCOUNT |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        query.putShort((short)id); // ID
        query.putShort((short)0); // Flags
        query.putShort((short)1); // QDCOUNT
        query.putShort((short)0); // ANCOUNT
        query.putShort((short)0); // NSCOUNT
        query.putShort((short)0); // ARCOUNT

        // Question section [RFC 4.1.2. Question section format]
        // 1 1 1 1 1 1
        // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // | |
        // / QNAME /
        // / /
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // | QTYPE |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // | QCLASS |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        // Split domain name into labels
        String[] labels = domainName.split("\\.");
        for (String label : labels) {
            query.put((byte)label.length()); // length byte
            query.put(label.getBytes(StandardCharsets.UTF_8)); // label bytes
        }
        query.put((byte)0); // zero length byte as end of qname

        query.putShort((short)1); // QTYPE (A record)
        query.putShort((short)1); // QCLASS (IN)

        return query.array();
    }

    static class NumberResult {
        long number;
        int nextIndex;
        NumberResult(long number, int nextIndex) {
            this.number = number;
            this.nextIndex = nextIndex;
        }
    }

    static class NameResult {
        String name;
        int nextIndex;
        NameResult(String name, int nextIndex) {
            this.name = name;
            this.nextIndex = nextIndex;
        }
    }

    // parse byte_length bytes from index as unsigned integer
    public static NumberResult parseUnsignedInt(int index, int byteLength, byte[] response) {
        ByteBuffer buffer = ByteBuffer.wrap(response, index, byteLength);
        buffer.order(ByteOrder.BIG_ENDIAN);
        long num;
        switch (byteLength) {
            case 1: num = buffer.get() & 0xFF; break;
            case 2: num = buffer.getShort() & 0xFFFF; break;
            case 4: num = buffer.getInt() & 0xFFFFFFFFL; break;
            default: throw new IllegalArgumentException("Unsupported byte length");
        }
        return new NumberResult(num, index + byteLength);
    }

    // parse name as label series from index
    public static NameResult parseName(int index, byte[] response) {
        StringBuilder name = new StringBuilder();
        int end = 0;
        boolean loop = true;
        int currentIndex = index;

        while (loop) {
            int labelLength = response[currentIndex] & 0xFF;
            if (labelLength == 0) {
                end = currentIndex + 1;
                loop = false;
            }
            // pointer
            else if (labelLength >= 0xC0) { // 11000000 in binary
                int offset = ((response[currentIndex] & 0x3F) << 8) + 
                           (response[currentIndex + 1] & 0xFF);
                end = currentIndex + 2;
                NameResult prevName = parseName(offset, response);
                name.append(prevName.name);
                break;
            }
            // label
            else {
                currentIndex++;
                String label = new String(response, currentIndex, labelLength, 
                                        StandardCharsets.UTF_8);
                name.append(label).append(".");
                currentIndex += labelLength;
            }
        }

        String result = name.toString();
        if (result.endsWith(".")) {
            result = result.substring(0, result.length() - 1);
        }
        return new NameResult(result, end);
    }

    // TODO: VICTORIA Implement this method to parse a single resource record
    // Should parse NAME, TYPE, CLASS, TTL, RDLENGTH, and RDATA
    public static ResourceRecord parseResourceRecord(int index, byte[] response) {
        // TODO: Parse resource record starting at index
        // Return ResourceRecord object with parsed data
        return null;
    }
        
        NameResult nameResult = parseName(index, response); //using the index and response to parse the name
        String name = nameResult.name; //storing the name result
        int currentIndex = nameResult.nextIndex; //storing the current index
    
        NumberResult typeResult = parseUnsignedInt(currentIndex, 2, response); //using the current index, 2 bytes, and the response to parse the type
        int type = (int) typeResult.number;//storing the result
        currentIndex = typeResult.nextIndex;//updating the current index
    
        NumberResult classResult = parseUnsignedInt(currentIndex, 2, response); //using the current index, 2 bytes, and the response to parse the class
        int rrClass = (int) classResult.number;//storing the parsed class
        currentIndex = classResult.nextIndex;//updating the current index
    
        NumberResult ttlResult = parseUnsignedInt(currentIndex, 4, response); //using the current index, 4 bytes, and the response to parse ttl
        long ttl = ttlResult.number;//storing the parsed ttl 
        currentIndex = ttlResult.nextIndex; //updating the current index
    
        NumberResult rdLengthResult = parseUnsignedInt(currentIndex, 2, response);//using the current index, 2 bytes, and response to parse rd length
        int rdLength = (int) rdLengthResult.number;//storing the parsed rdlength
        currentIndex = rdLengthResult.nextIndex;//updating the current index
    
        byte[] rdata = new byte[rdLength];//creating new array using rdlength as the size
        
        for (int i = 0; i < rdLength; i++) { //copying bytes from the response into the array
            rdata[i] = response[currentIndex + i];
        }
    
        ResourceRecord resourceRecord = new ResourceRecord(name, type, rrClass, ttl, rdLength, rdata);//creating object
        return resourceRecord;//returning resourceRecord
}

    // TODO: VICTORIA Implement this method to parse all resource records in a section
    public static List<ResourceRecord> parseResourceRecords(int index, int count, byte[] response) {
        // TODO: Parse 'count' number of resource records starting at index
        // Return list of ResourceRecord objects and update index
        return null;
        List<ResourceRecord> records = new ArrayList<>();//creating records array list
        int currentIndex = index;//creating current index value
        
        for (int i = 0; i < count; i++) { //for loop to parse using current index and response and then add then add to the array list
            ResourceRecord record = parseResourceRecord(currentIndex, response);
            records.add(record);
            currentIndex = // still need to calculate next index****;
        }
        
        return records;
    }

    // TODO: VICTORIA Implement this method to convert IP address from RDATA to string format
    public static String parseIPAddress(byte[] rdata) {
        // TODO: Convert 4-byte IPv4 address to dotted decimal notation
        return null;
    }

    // TODO: LAISHA Implement this method to extract domain name from RDATA for NS records
    public static String parseNSRecord(byte[] rdata, byte[] fullResponse) {
        // TODO: Parse domain name from NS record RDATA
        // Note: May need to handle compression pointers
        return null;
    }

    // TODO: LAISHA Implement this method to find IP address for a given domain name in Additional section
    public static String findIPInAdditional(String domainName, List<ResourceRecord> additionals) {
        // TODO: Search through additional records to find A record for domainName
        // Return IP address as string, or null if not found
        return null;
    }

    // TODO:LAISHA Implement this method to extract NS server names from Authority section
    public static List<String> extractNSServers(List<ResourceRecord> authorities, byte[] fullResponse) {
        // TODO: Extract all NS server names from authority section
        // Return list of server domain names
        return null;
    }

    // TODO: LAISHA Implement this method to find the next DNS server to query
    public static String selectNextServer(List<String> nsServers, List<ResourceRecord> additionals) {
        // TODO: For each NS server, try to find its IP in additional section
        // Return IP address of first available server, or null if none found
        return null;
    }

    // parse DNS response
    public static DNSResponse parseResponse(byte[] response) {
        System.out.println("----- parse response -----");
        DNSResponse dnsResponse = new DNSResponse();
        int index = 0;

        System.out.println("Header section [RFC 4.1.1. Header section format]");

        // Header section [RFC 4.1.1. Header section format]
        NumberResult result = parseUnsignedInt(index, 2, response);
        dnsResponse.id = (int)result.number;
        System.out.println("ID: " + result.number);
        index = result.nextIndex;

        result = parseUnsignedInt(index, 2, response);
        dnsResponse.flags = (int)result.number;
        index = result.nextIndex; // skip flags for now

        result = parseUnsignedInt(index, 2, response);
        dnsResponse.qdcount = (int)result.number;
        System.out.println("QDCOUNT: " + result.number);
        index = result.nextIndex;

        result = parseUnsignedInt(index, 2, response);
        dnsResponse.ancount = (int)result.number;
        System.out.println("ANCOUNT: " + result.number);
        index = result.nextIndex;

        result = parseUnsignedInt(index, 2, response);
        dnsResponse.nscount = (int)result.number;
        System.out.println("NSCOUNT: " + result.number);
        index = result.nextIndex;

        result = parseUnsignedInt(index, 2, response);
        dnsResponse.arcount = (int)result.number;
        System.out.println("ARCOUNT: " + result.number);
        index = result.nextIndex;

        System.out.println("Question section [RFC 4.1.2. Question section format]");

        // Question section
        NameResult nameResult = parseName(index, response);
        dnsResponse.qname = nameResult.name;
        System.out.println("QNAME: " + nameResult.name);
        index = nameResult.nextIndex;

        result = parseUnsignedInt(index, 2, response);
        dnsResponse.qtype = (int)result.number;
        System.out.println("QTYPE: " + result.number);
        index = result.nextIndex;

        result = parseUnsignedInt(index, 2, response);
        dnsResponse.qclass = (int)result.number;
        System.out.println("QCLASS: " + result.number);
        index = result.nextIndex;

        // TODO: VICTORIA Parse Answer section
        if (dnsResponse.ancount > 0) {
            System.out.println("Answer section:");
            // dnsResponse.answers = parseResourceRecords(index, dnsResponse.ancount, response);
            // Update index after parsing
        }

        // TODO: LAISHA  Parse Authority section  
        if (dnsResponse.nscount > 0) {
            System.out.println("Authority section:");
            // dnsResponse.authorities = parseResourceRecords(index, dnsResponse.nscount, response);
            // Update index after parsing
        }

        // TODO: HAFSAH Parse Additional section
        if (dnsResponse.arcount > 0) {
            System.out.println("Additional section:");
            dnsResponse.additionals = parseResourceRecords(index, dnsResponse.arcount, response);
        }

        return dnsResponse;
    }

    // TODO: HAFSAH Implement this method to send DNS query and receive response
    public static DNSResponse sendQuery(String domainName, String serverIP, int queryId) throws Exception {
        // Create UDP socket
        DatagramSocket socket = new DatagramSocket();
        socket.setSoTimeout(5000); // 5 second timeout
        
        try {
            // Create and send DNS query
            byte[] query = createQuery(queryId, domainName);
            DatagramPacket packet = new DatagramPacket(query, query.length, 
                                                     InetAddress.getByName(serverIP), 53);
            socket.send(packet);
            
            // Receive response
            byte[] response = new byte[2048];
            DatagramPacket responsePacket = new DatagramPacket(response, response.length);
            socket.receive(responsePacket);
            
            // Extract actual response data
            byte[] actualResponse = new byte[responsePacket.getLength()];
            System.arraycopy(response, 0, actualResponse, 0, responsePacket.getLength());
            
            // Parse and return DNS response
            return parseResponse(actualResponse);
            
        } finally {
            socket.close();
        }
    }

    // TODO HAFSAH: Implement this method to perform iterative DNS resolution
    public static void performIterativeResolution(String domainName, String rootServerIP) throws Exception {
        String currentServerIP = rootServerIP;
        int queryId = 1;
        
        System.out.println("Starting iterative DNS resolution for: " + domainName);
        System.out.println("Root server: " + rootServerIP);
        
        while (true) {
            System.out.println("\nQuerying server: " + currentServerIP);
            
            // Send query to current server
            DNSResponse response = sendQuery(domainName, currentServerIP, queryId++);
            
            // Check if we got an answer
            if (response.ancount > 0) {
                System.out.println("Answer found!");
                displayFinalIPs(response.answers);
                return;
            }
            
            // No answer, check authority section for NS servers
            if (response.nscount > 0) {
                List<String> nsServers = extractNSServers(response.authorities, null); // fullResponse parameter needed
                
                // Find IP addresses for NS servers in additional section
                String nextServerIP = selectNextServer(nsServers, response.additionals);
                
                if (nextServerIP != null) {
                    currentServerIP = nextServerIP;
                    continue;
                }
            }
            
            // If we can't find next server, resolution failed
            System.out.println("DNS resolution failed - no answer and no next server available");
            return;
        }
    }

    // TODO: HAFSAH Implement this method to display final IP addresses
    public static void displayFinalIPs(List<ResourceRecord> answers) {
        System.out.println("Final IP addresses:");
        
        for (ResourceRecord answer : answers) {
            if (answer.type == 1) { // A record
                String ipAddress = parseIPAddress(answer.rdata);
                System.out.println("  " + answer.name + " -> " + ipAddress);
            }
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.out.println("Usage: mydns domain-name root-dns-ip");
            System.exit(1);
        }

        String domainName = args[0];
        String rootDnsIp = args[1];

        // Replace basic implementation with iterative resolution
        performIterativeResolution(domainName, rootDnsIp);
    }