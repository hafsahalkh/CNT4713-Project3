import java.net.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

public class mydns {
    // create DNS query message
    public static byte[] createQuery(int id, String domainName) {
        // Header section
        ByteBuffer query = ByteBuffer.allocate(1024);
        query.order(ByteOrder.BIG_ENDIAN);

        // Query header [RFC 4.1.1. Header section format]
        //                                 1  1  1  1  1  1
        // 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                      ID                       |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                    QDCOUNT                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                    ANCOUNT                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                    NSCOUNT                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                    ARCOUNT                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        query.putShort((short)id);    // ID
        query.putShort((short)0);     // Flags
        query.putShort((short)1);     // QDCOUNT
        query.putShort((short)0);     // ANCOUNT
        query.putShort((short)0);     // NSCOUNT
        query.putShort((short)0);     // ARCOUNT

        // Question section [RFC 4.1.2. Question section format]
        //                             1  1  1  1  1  1
        // 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                                               |
        // /                     QNAME                     /
        // /                                               /
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                     QTYPE                     |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                     QCLASS                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        // Split domain name into labels
        String[] labels = domainName.split("\\.");
        for (String label : labels) {
            query.put((byte)label.length());           // length byte
            query.put(label.getBytes(StandardCharsets.UTF_8));  // label bytes
        }
        query.put((byte)0);  // zero length byte as end of qname
        query.putShort((short)1);  // QTYPE
        query.putShort((short)1);  // QCLASS
        
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

    // parse DNS response
    public static void parseResponse(byte[] response) {
        System.out.println("----- parse response -----");
        int index = 0;

        System.out.println("Header section [RFC 4.1.1. Header section format]");
        // Header section [RFC 4.1.1. Header section format]
        //                                 1  1  1  1  1  1
        // 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                      ID                       |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                    QDCOUNT                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                    ANCOUNT                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                    NSCOUNT                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                    ARCOUNT                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        NumberResult result = parseUnsignedInt(index, 2, response);
        System.out.println("ID: " + result.number);
        index = result.nextIndex;

        index += 2; // skip flags

        result = parseUnsignedInt(index, 2, response);
        System.out.println("QDCOUNT: " + result.number);
        index = result.nextIndex;

        result = parseUnsignedInt(index, 2, response);
        System.out.println("ANCOUNT: " + result.number);
        index = result.nextIndex;

        result = parseUnsignedInt(index, 2, response);
        System.out.println("NSCOUNT: " + result.number);
        index = result.nextIndex;

        result = parseUnsignedInt(index, 2, response);
        System.out.println("ARCOUNT: " + result.number);
        index = result.nextIndex;

        System.out.println("Question section [RFC 4.1.2. Question section format]");
        // Question section [RFC 4.1.2. Question section format]
        //                                 1  1  1  1  1  1
        // 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                                               |
        // /                     QNAME                     /
        // /                                               /
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                     QTYPE                     |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                     QCLASS                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        NameResult nameResult = parseName(index, response);
        System.out.println("QNAME: " + nameResult.name);
        index = nameResult.nextIndex;

        result = parseUnsignedInt(index, 2, response);
        System.out.println("QTYPE: " + result.number);
        index = result.nextIndex;

        result = parseUnsignedInt(index, 2, response);
        System.out.println("QCLASS: " + result.number);
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.out.println("Usage: mydns domain-name root-dns-ip");
            System.exit(1);
        }
        
        String domainName = args[0];
        String rootDnsIp = args[1];

        // Create UDP socket
        DatagramSocket socket = new DatagramSocket();

        // Send DNS query
        int id = 1;
        byte[] query = createQuery(id, domainName);
        DatagramPacket packet = new DatagramPacket(query, query.length, 
                                InetAddress.getByName(rootDnsIp), 53);
        socket.send(packet);

        // Receive response
        byte[] response = new byte[2048];
        DatagramPacket responsePacket = new DatagramPacket(response, response.length);
        socket.receive(responsePacket);

        // Parse response
        byte[] actualResponse = new byte[responsePacket.getLength()];
        System.arraycopy(response, 0, actualResponse, 0, responsePacket.getLength());
        parseResponse(actualResponse);

        socket.close();
    }
}