package ro.linic.cloud.master.authorizer.common;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Component;

@Component
public class I18n {
	@Autowired private MessageSource messageSource;

	public String msg(final String code) {
		// Attention LocaleContextHolder.getLocale() is thread based,
		// maybe you need some fallback locale
		return messageSource.getMessage(code, null, LocaleContextHolder.getLocale());
	}
	
	public String msg(final String code, final Object... args) {
		// Attention LocaleContextHolder.getLocale() is thread based,
		// maybe you need some fallback locale
		return messageSource.getMessage(code, args, LocaleContextHolder.getLocale());
	}
}