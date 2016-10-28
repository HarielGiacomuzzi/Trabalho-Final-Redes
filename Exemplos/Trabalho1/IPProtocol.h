#ifndef IPPROTOCOL_H
#define IPPROTOCOL_H

enum Protocol{
    ARP = 0x0806,
    IP = 0x0800
};

enum TypeOfService{
    ICMP = 0x01,
    UDP = 0x11,
    TCP = 0x06,
};

enum UDPService{
    DNS = 0x0035
};

enum TCPService{
    HTTP = 0x0050
};

class IPProtocol
{
    public:
        IPProtocol();
        ~IPProtocol();
        // sendś back the tipe of the protocol inside
        int identifyProtocol();
        //sends back the size of the package in bytes
        int identifyPackageSize();
        // sets the current package
        void setPackage(unsigned char *package);
        // sends back the type of service inside the IP protocol
        int identifyTypeOfService();
        // sends back the number of the destination port
        int getDestinationPort();
        // sends back the number of the source port
        int getSourcePort();
        // get the website of a HTTP package
        int* getDestinationIPFromHTTP();
        int* getSourceIPFromHTTP();
        // identifies if a package is from HTTP type
        bool identifyHTTP();

    protected:
    private:
        unsigned char *package;
};

#endif // IPPROTOCOL_H
