package local.rdps.asp.parsers;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.MalformedInputException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.Callable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * <p>
 * This class is responsible for parsing the actual logs and pumping the events into a map that is then returned
 * to the caller.
 * </p>
 *
 * @author DaRon
 * @since 1.0
 */
public class ActiveSyncLogParser implements Callable<Map<String, Map<Instant, StringBuilder>>> {
	// A pattern defining a start of an entry
	private static final Pattern ENTRY_SEPARATOR = Pattern.compile("\\h*Log Entry: \\d+\\h*");
	// A pattern defining the event timestamp
	private static final Pattern REQUEST_TIME = Pattern.compile(
			"\\h*RequestTime\\h*:[\\h\\v]*(?<month>\\d{2})/(?<day>\\d{2})/(?<year>\\d{4})\\h+(?<time>(?:\\d{1,2}:){2}\\d{2})",
			Pattern.MULTILINE);
	// A pattern defining the device ID
	private static final Pattern REQUESTOR_ID = Pattern.compile("DeviceId=(?<DID>[^&]+)");
	// What charset we are using to parse the file
	private int charset;
	// A map containing all of the events in the log file, nicely organised
	private final Map<String, Map<Instant, StringBuilder>> data;
	// Our log file (in all of its glory)
	private final Path logFile;

	/**
	 * <p>
	 * This method extracts the device id (DID) from the given entry.
	 * </p>
	 *
	 * @param entry The entry from which we are to extract a timestamp
	 * @return An optional containing the device ID
	 */
	private static Optional<String> getDid(final StringBuilder entry) {
		final Matcher matcher = ActiveSyncLogParser.REQUESTOR_ID.matcher(entry);
		if (matcher.find()) {
			return Optional.ofNullable(matcher.group("DID"));
		}

		return Optional.empty();
	}

	/**
	 * <p>
	 * This method parses the data in the given entry, retrieving the time that the
	 * event occured.
	 * </p>
	 *
	 * @param entry The entry from which we are to extract a timestamp
	 * @return An optional containing the timestamp for this event
	 */
	private static Optional<Instant> getInstant(final StringBuilder entry) {
		final Matcher matcher = ActiveSyncLogParser.REQUEST_TIME.matcher(entry);
		if (matcher.find()) {
			final String month = matcher.group("month");
			final String day = matcher.group("day");
			final String year = matcher.group("year");
			final String time = matcher.group("time");
			if ((month == null) || (day == null) || (year == null) || (time == null)) {
				return Optional.empty();
			}

			return Optional.of(Instant.parse(year + '-' + month + '-' + day + 'T' + time + ".00Z"));
		}

		return Optional.empty();
	}

	/**
	 * <p>
	 * This constructor gives us a shiny, new ActiveSync log parser.
	 * </p>
	 *
	 * @param logFile The log file to parse
	 */
	public ActiveSyncLogParser(final Path logFile) {
		this.logFile = logFile;
		this.data = new HashMap<>(8);
	}

	private void addEntryToMap(final String deviceId, final Instant date, final StringBuilder entry) {
		Map<Instant, StringBuilder> entries = this.data.get(deviceId);
		if (entries == null) {
			entries = new TreeMap<>();
			this.data.put(deviceId, entries);
		}
		entries.put(date, entry);
	}

	/**
	 * <p>
	 * This method returns a map of maps, with the key being the device ID.  The value consists of a map
	 * containing the time when the event happened and the event text.
	 * </p>
	 */
	@Override
	public Map<String,
			Map<Instant, StringBuilder>> call() throws IOException {
		StringBuilder entry = null;
		Optional<Instant> date = Optional.empty();
		Optional<String> did = Optional.empty();
		try (BufferedReader reader = Files.newBufferedReader(this.logFile, FileParser.CHARSETS[this.charset])) {
			String line;
			while ((line = reader.readLine()) != null) {
				// If we are the start of a new entry, we need to clear out the reference to the old one since there's
				// no longer anything to append
				if (ActiveSyncLogParser.ENTRY_SEPARATOR.matcher(line).find()) {
					if (entry != null) {
						entry.trimToSize();
					}
					entry = null;
					date = Optional.empty();
					did = Optional.empty();

					// If we are the start of an Apache access entry that we care about, let's push it and collect the
					// whole entry
					entry = new StringBuilder(line.length() + 512);
					entry.append(line);
				}
				// Keep appending to the existing entry if our line is part of said entry
				else if (entry != null) {
					entry.append(System.lineSeparator()).append(line);
					if (!date.isPresent() || !did.isPresent()) {
						if (!date.isPresent()) {
							date = ActiveSyncLogParser.getInstant(entry);
							if (date.isPresent() && did.isPresent()) {
								addEntryToMap(did.get(), date.get(), entry);
							}
						} else {
							did = ActiveSyncLogParser.getDid(entry);
							if (did.isPresent()) {
								addEntryToMap(did.get(), date.get(), entry);
							}
						}
					}
				}
			}

		} catch (final MalformedInputException e) {
			if (this.charset < (FileParser.CHARSETS.length - 1)) {
				this.charset++;
				call();
			} else {
				throw e;
			}
		}

		return this.data;
	}
}
