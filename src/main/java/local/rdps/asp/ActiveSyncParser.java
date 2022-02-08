package local.rdps.asp;

import local.rdps.asp.parsers.ActiveSyncLogParser;
import org.tukaani.xz.FilterOptions;
import org.tukaani.xz.LZMA2Options;
import org.tukaani.xz.UnsupportedOptionsException;
import org.tukaani.xz.X86Options;
import org.tukaani.xz.XZ;
import org.tukaani.xz.XZOutputStream;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;
import java.util.regex.Pattern;

/**
 * <p>
 * This class is the main class for the ActiveSync Parser, a tool designed to parse active sync logs
 * and give digital forensics experts data regarding which devices, which IP addresses pulled what
 * emails and performed other such activity against an Exchange server (including Office365).
 * </p>
 *
 * @author DaRon
 * @since 1.0
 */
public class ActiveSyncParser {
	private static final String BLOCK_SEPARATOR_STRING = "----------";
	// Our thread pool (we like to do // work)
	private static final ExecutorService EXECUTOR = Executors.newFixedThreadPool(4);
	// Our pretty little data
	private static final SortedMap<String, Map<Instant, String>> MAP = new TreeMap<>();
	// Each of our parsers
	private static List<FutureTask<Map<String, Map<Instant, StringBuilder>>>> PARSERS = new LinkedList<>();
	// If the user has specified that we only keep entries tied to a specific device ID or IDs, that information
	// is contained herein
	private static final Set<String> KEYS_TO_KEEP = new HashSet<>(4);

	/**
	 * <p>
	 * This method grabs all of the files from within a folder. If the provided File is a file, we verify that it is
	 * readable first. Otherwise, we check if it's a folder and then grab the files or if it is a regular expression. If
	 * it is a regular expression, we use the regex to pull all matching directories and their files or matching files.
	 * </p>
	 *
	 * @param file A directory, file, or regex from which we will extract log data
	 */
	private static void gatherFiles(final File file) {
		final Path filePath = file.toPath();
		if (file.exists()) {
			// Check if you gave us a directory
			if (Files.isDirectory(filePath)) {
				Arrays.stream(file.listFiles()).distinct().forEach(ActiveSyncParser::runParserIfWithinTime);
			}
			// Check if you gave us a file
			else if (Files.isReadable(filePath)) {
				ActiveSyncParser.parseFile(filePath);
			} else {
				System.err.println("The specified file is not readable: " + filePath);
			}
		}
		// Let's see if you gave us a regex for the filename portion...
		else if (filePath.getFileName() != null) {
			// Let's assume we have a parent
			if (filePath.getParent() != null) {
				// For the record, this would normally be dangerous, but in this case, if you are doing a regex injection
				// on this, it only hurts you, the caller of this application... so...
				final Pattern fileFilter = Pattern.compile(filePath.getFileName().toString());
				if (Files.isDirectory(filePath.getParent())) {
					Arrays.stream(filePath.getParent().toFile().listFiles()).distinct()
							.filter(item -> fileFilter.matcher(item.getName()).matches() == true)
							.forEach(ActiveSyncParser::runParserIfWithinTime);
				}
			}
		} else {
			System.err.println("Unable to find the specified file: " + filePath);
		}
	}

	/**
	 * <p>
	 * This method calls to parse the file if the file is a regular file.
	 * </p>
	 *
	 * @param filePath The Path to the file that we want to parse
	 */
	private static void parseFile(final Path filePath) {
		if ((filePath != null) && Files.isRegularFile(filePath)) {
			final FutureTask<Map<String, Map<Instant, StringBuilder>>> parser = new FutureTask<>(
					new ActiveSyncLogParser(filePath));
			ActiveSyncParser.PARSERS.add(parser);
			ActiveSyncParser.EXECUTOR.execute(parser);
		} else {
			System.err.println("The specified file is not a regular file: " + filePath);
		}
	}

	/**
	 * <p>
	 * This method prints the report to stdout.
	 * </p>
	 */
	private static void printToStdout() {
		System.out.println("***************");
		System.out.println("**ALL DEVICES**");
		System.out.println("***************");
		ActiveSyncParser.MAP.keySet().forEach(System.out::println);
		System.out.println();

		for (final Entry<String, Map<Instant, String>> entry : ActiveSyncParser.MAP.entrySet()) {
			if (!ActiveSyncParser.KEYS_TO_KEEP.isEmpty()) {
				if (!ActiveSyncParser.KEYS_TO_KEEP.contains(entry.getKey())) {
					continue;
				}
			}

			System.out.println();
			System.out.println("***************");
			System.out.println("***************");
			System.out.println("*** DEVICE ****");
			System.out.println(entry.getKey());
			System.out.println("***************");
			System.out.println("***************");
			System.out.println();

			entry.getValue().entrySet().stream().map(Entry::getValue).map(String::trim)
					.map(string -> ActiveSyncParser.BLOCK_SEPARATOR_STRING + System.lineSeparator() + string +
							System.lineSeparator() + ActiveSyncParser.BLOCK_SEPARATOR_STRING)
					.forEachOrdered(System.out::println);
		}
	}

	/**
	 * <p>
	 * This method runs the parse against any file that is within the designated time. If the File is really a
	 * directory, we call to have the files gathered from within.
	 * </p>
	 *
	 * @param item The file or directory to parse
	 */
	private static void runParserIfWithinTime(final File item) {
		if (item.isFile()) {
			// Ignore modSecurity logs because they are verbose and unnecessary, as well as anything that we cannot read
			if (item.canRead()) {
				ActiveSyncParser.parseFile(item.toPath());
			}
		} else if (item.isDirectory()) {
			ActiveSyncParser.gatherFiles(item);
		}
	}

	/**
	 * <p>
	 * This method serves as the entry point for the ASP application.
	 * </p>
	 *
	 * @param args Our arguments (which must be coherent, else we'll lose the debate!)
	 */
	public static void main(final String[] args) {
		try {
			if (args.length > 0) {
				for (int i = 0; i < args.length; i++) {
					String arg = args[i];
					if ("--keep".equals(arg)) {
						if ((i + 1) < args.length) {
							i++;
							arg = args[i];
							Arrays.stream(arg.split("\\s*,\\s*")).forEach(ActiveSyncParser.KEYS_TO_KEEP::add);
						}
					} else {
						ActiveSyncParser.gatherFiles(new File(arg));
					}
				}
			}

			if ((ActiveSyncParser.PARSERS != null) && !ActiveSyncParser.PARSERS.isEmpty()) {
				for (final FutureTask<Map<String, Map<Instant, StringBuilder>>> task : ActiveSyncParser.PARSERS) {
					try {
						final Map<String, Map<Instant, StringBuilder>> taskMap = task.get();
						for (final Entry<String, Map<Instant, StringBuilder>> taskMapEntry : taskMap.entrySet()) {
							final Map<Instant, String> entries = ActiveSyncParser.MAP.get(taskMapEntry.getKey());
							if (entries == null) {
								final Map<Instant, StringBuilder> taskEntries = taskMapEntry.getValue();
								if ((taskEntries != null) && !taskEntries.isEmpty()) {
									final Map<Instant, String> map = new TreeMap<>();
									taskMapEntry.getValue().forEach((k, v) -> map.put(k, v.toString().trim()));
									ActiveSyncParser.MAP.put(taskMapEntry.getKey(), map);
								}
							} else {
								taskMapEntry.getValue().entrySet().stream().forEach(
										entry -> entries.put(entry.getKey(), entry.getValue().toString().trim()));
							}
						}
					} catch (InterruptedException | ExecutionException e) {
						e.printStackTrace();
					}
				}
			}
		} finally {
			ActiveSyncParser.EXECUTOR.shutdown();
		}

		ActiveSyncParser.printToStdout();
	}

	/**
	 * <p>
	 * This constructor prevents instantiation by other classes.
	 * </p>
	 */
	private ActiveSyncParser() {
		// Do nothing
	}
}
