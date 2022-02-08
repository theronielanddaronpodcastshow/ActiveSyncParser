package local.rdps.asp.parsers;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * <p>
 * This class contains the general information and data used by all parsers.
 * </p>
 *
 * @author DaRon
 * @since 1.0
 */
public class FileParser {
	static final Charset[] CHARSETS = {
			StandardCharsets.US_ASCII,
			StandardCharsets.UTF_8,
			StandardCharsets.UTF_16,
			StandardCharsets.ISO_8859_1
	};
}
