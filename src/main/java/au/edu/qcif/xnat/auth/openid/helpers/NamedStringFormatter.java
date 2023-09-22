package au.edu.qcif.xnat.auth.openid.helpers;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.concurrent.atomic.AtomicInteger;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class NamedStringFormatter {
    private static final Pattern EXTRACTOR = Pattern.compile("\\[([a-zA-Z0-9_.]+)]");
    private Map<String, Object> data;

    public NamedStringFormatter(Map<String, Object> data) {
        this.data = data;
    }

    public String getValue(String key) {
        log.debug("fieldName: "+ key);
        String[] parts = key.split("\\.");
        

        // Traverse the nested Object (assuming containing Maps and/or Lists) using the splitted parts
        Object result = this.data;
        for (String part : parts) {
            if (result instanceof Map && ((Map<?, ?>) result).containsKey(part)) {
                result = ((Map<?,?>) result).get(part);
            } else if (result instanceof List && ((List<?>) result).size() >= Integer.valueOf(part)) {
                result = ((List<?>) result).get(Integer.valueOf(part));
            } else {
                result = null;
                break;
            }
        }

        //TDOD: catch exceptions when casting fails
        String value = (String) result;
        log.debug("* Value from data object: " + value);
        return value;
    }

    public String format(final String usernamePattern) {
        final String  pattern = usernamePattern;
        final Matcher matcher = EXTRACTOR.matcher(pattern);

        HashMap<String, String> pairs = new HashMap<>();

        final AtomicInteger index = new AtomicInteger();
        while (matcher.find(index.get())) {
            pairs.put(matcher.group(0), matcher.group(1));
            index.set(matcher.end());
        }

        String converted = pattern;
        for (final String key : pairs.keySet()) {
            converted = converted.replace(key, getValue(pairs.get(key)));
        }
        return converted;
    }
}
