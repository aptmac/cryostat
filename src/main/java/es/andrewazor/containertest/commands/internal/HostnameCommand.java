package es.andrewazor.containertest.commands.internal;

import es.andrewazor.containertest.JMCConnection;

class HostnameCommand extends AbstractCommand {
    HostnameCommand(JMCConnection connection) {
        super(connection);
    }

    @Override
    public String getName() {
        return "hostname";
    }

    @Override
    public boolean validate(String[] args) {
        return args.length == 0;
    }

    @Override
    public void execute(String[] args) throws Exception {
        System.out.println(String.format("\t%s", connection.getRecordingExporter().getHostName()));
    }
}