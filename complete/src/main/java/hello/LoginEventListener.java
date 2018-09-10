package hello;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
public class LoginEventListener {

	private static final Logger logger = LoggerFactory.getLogger(LoginEventListener.class);

	@EventListener
	public void logRememberMeSuccess(InteractiveAuthenticationSuccessEvent event) {
		Authentication authentication = event.getAuthentication();
		if (RememberMeAuthenticationToken.class.isAssignableFrom(authentication.getClass())) {
			logger.info("Remember me login success!");
		}
	}
}
