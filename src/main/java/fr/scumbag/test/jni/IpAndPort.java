package fr.scumbag.test.jni;

public class IpAndPort {

    private String ip;
    private Long port;

    @Override
    public String toString() {
        return "IpAndPort{" +
                "ip='" + ip + '\'' +
                ", port=" + port +
                '}';
    }

    public Long getPort() {
        return port;
    }

    public void setPort(Long port) {
        this.port = port;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }
}
