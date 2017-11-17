package fr.scumbag.test.jni;

public class App {

    static {
        System.loadLibrary("socketstat");
    }

    private native IpAndPort[] get_tcp_data() throws Exception;

    public static void main(String[] args) {
        App app = new App();
        while (true) {
            try {
                app.get_tcp_data();
            } catch(Exception e) {
                e.printStackTrace();
            }
        }
    }
}
