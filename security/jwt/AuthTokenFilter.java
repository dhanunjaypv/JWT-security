package com.sailotech.tm.security.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.sailotech.tm.UserContextHolder;
import com.sailotech.tm.dao.SecurityUserDetails;
import com.sailotech.tm.dto.LoginDetails;
import com.sailotech.tm.security.services.UserDetailsServiceImpl;
import com.sailotech.tm.util.CommonUtilities;
import com.sailotech.tm.util.Constants;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class AuthTokenFilter extends OncePerRequestFilter {

	@Autowired
	private JwtUtils jwtUtils;

	@Autowired
	private CommonUtilities utilities;
	

	@Autowired
	private UserContextHolder userContextHolder;
	
	@Autowired
	private UserDetailsServiceImpl userDetailsService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		final String headerAuth = request.getHeader(HttpHeaders.AUTHORIZATION);

		if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
			String jwt = headerAuth.substring(7, headerAuth.length());
			try {
				if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
					String username = jwtUtils.getUserNameFromJwtToken(jwt);
					String type =jwtUtils.getUserTypeFromJwtToken(jwt);
					String un = String.format("%s%s%s", username.trim(), Constants.SPLIT_VARIABLE, type);
					
					UserDetails userDetails = userDetailsService.loadUserByUsername(un);
					UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
							userDetails, null, userDetails.getAuthorities());
					authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

					SecurityContextHolder.getContext().setAuthentication(authentication);
					LoginDetails loginDetails=utilities.covertUserDtoTOLoginDetails((SecurityUserDetails)userDetails);
					userContextHolder.setLoginDetails(loginDetails);
					
				}
				
			} catch (Exception e) {
				logger.error("Cannot set user authentication: {}", e);
			}
		}
		userContextHolder.setTimeZone(request.getHeader("timezone"));
		userContextHolder.setOffSet(request.getHeader("offset"));

		filterChain.doFilter(request, response);
	}
}
