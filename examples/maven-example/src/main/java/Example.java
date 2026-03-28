import org.apache.commons.lang3.StringUtils;

/**
 * Minimal example: use commons-lang3 to demonstrate the Shieldoo Maven proxy.
 */
public class Example {

    public static void main(String[] args) {
        String message = "hello from shieldoo gate";

        System.out.println("Original:    " + message);
        System.out.println("Capitalized: " + StringUtils.capitalize(message));
        System.out.println("Reversed:    " + StringUtils.reverse(message));
        System.out.println("Is blank:    " + StringUtils.isBlank(message));
        System.out.println();
        System.out.println("commons-lang3 loaded successfully!");
        System.out.println("Done!");
    }
}
