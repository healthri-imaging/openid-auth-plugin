package au.edu.qcif.xnat.auth.openid.helpers;

import java.text.MessageFormat;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class NamedStringFormatter {
    private Map<String, Object> data = new HashMap<>();

    public NamedStringFormatter(Map<String, Object> data) {
        this.data = data;
    }

    public void setData(Map<String, Object> data) {
        this.data = data;
    }

    public String format(String formatString) {
        // Replace placeholders in the format string using MessageFormat
        log.debug("Start of formatter, using: {}", formatString);
        Object[] args = new Object[data.size()];
        log.debug("Created Object[]");
        int index = 0;
        for (Map.Entry<String, Object> entry : data.entrySet()) {
            log.debug("=> [{}] entry: {}, value: {}", index, entry, entry.getValue());
            args[index++] = entry.getValue();
        }
        
        log.debug("Args: {}", args);
        String formattedString = MessageFormat.format(formatString, args);
        log.debug("formattedString first pass: {}", formattedString);

        // Now, let's handle list indexing
        for (Map.Entry<String, Object> entry : data.entrySet()) {
            String placeholder = "{" + entry.getKey() + ".";
            
            log.debug("Placeholder: ", placeholder);

            if (formattedString.contains(placeholder)) {
                Object value = entry.getValue();
                log.debug("Value: {}", value);
                log.debug("value type: {}", value.getClass());
                if (value instanceof List) {
                    List<?> list = (List<?>) value;
                    for (int i = 0; i < list.size(); i++) {
                        String listPlaceholder = placeholder + i + "}";
                        formattedString = formattedString.replace(listPlaceholder, list.get(i).toString());
                    }
                }
            }
        }

        return formattedString;
    }

}
