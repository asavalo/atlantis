package sample;

public class BugOne {
    public void bug(byte[] data) throws Throwable {
        String[] cmds = new String(data).split("\0");
        new ProcessBuilder(cmds).start();
    }

    public void bug2(byte[] data) throws Throwable {
        if (data.length != 10) {
            return;
        }

        String[] cmds = new String(data).split("\0");
        new ProcessBuilder(cmds).start();
    }
}
