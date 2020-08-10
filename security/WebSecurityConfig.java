package com.sailotech.tm.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.sailotech.tm.security.jwt.AuthEntryPointJwt;
import com.sailotech.tm.security.jwt.AuthTokenFilter;
import com.sailotech.tm.security.services.UserDetailsServiceImpl;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private UserDetailsServiceImpl userDetailsService;

	@Autowired
	private AuthEntryPointJwt unauthorizedHandler;

	@Autowired
	private AuthTokenFilter authTokenFilter;

	@Override
	public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
		authenticationManagerBuilder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
	}

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable().authorizeRequests()
		.antMatchers("/patient/login").permitAll()
		.antMatchers("/physician/validate/**").permitAll()
		.antMatchers("/patient/validate/**").permitAll()
		.antMatchers("/search/**").permitAll()
		.antMatchers("/payment/callBack").permitAll()
		.antMatchers(HttpMethod.POST, "/physician/").permitAll()
		.antMatchers(HttpMethod.POST, "/patient/").permitAll()
		.antMatchers(HttpMethod.POST, "/patient/verify/mobile/otp").permitAll()
		.antMatchers(HttpMethod.POST, "/patient/forget/password").permitAll()
		.antMatchers(HttpMethod.POST, "/patient/forget/password/send").permitAll()
		.antMatchers(HttpMethod.POST, "/physician/forget/password").permitAll()
		.antMatchers(HttpMethod.POST, "/physician/forget/password/send").permitAll()
		.antMatchers("/admin/login").permitAll()
		.antMatchers("/physician/login").permitAll()
		.antMatchers("/signal").permitAll()
		.antMatchers(HttpMethod.GET,"/physician/{^[\\d]$}").permitAll()
				.antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
				.anyRequest()
				.authenticated()
//				.permitAll()
				.and()
				.exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and().sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		http.addFilterBefore(authTokenFilter, UsernamePasswordAuthenticationFilter.class);
	}
}