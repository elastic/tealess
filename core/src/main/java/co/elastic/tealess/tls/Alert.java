package co.elastic.tealess.tls;

public class Alert implements TLSMessage {
    private final AlertLevel alertLevel;
    private final AlertDescription alertDescription;

    public Alert(AlertLevel alertLevel, AlertDescription alertDescription) {
        this.alertLevel = alertLevel;
        this.alertDescription = alertDescription;
    }

    public String toString() {
        return String.format("Alert[%s, %s]", alertLevel, alertDescription);
    }
}
