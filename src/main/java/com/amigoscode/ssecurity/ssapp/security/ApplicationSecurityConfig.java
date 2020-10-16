package com.amigoscode.ssecurity.ssapp.security;

import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {
	private final PasswordEncoder passwordEncoder;
	
	@Autowired
	public ApplicationSecurityConfig(PasswordEncoder passwordEncoder){
		this.passwordEncoder = passwordEncoder;
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.csrf().disable()
			.authorizeRequests()
			.antMatchers("/", "index", "/css/*", "/js/*").permitAll()
			.antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())
//			.antMatchers(HttpMethod.DELETE, "management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
//			.antMatchers(HttpMethod.POST, "management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
//			.antMatchers(HttpMethod.PUT, "management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
//			.antMatchers(HttpMethod.GET, "management/api/**").hasAnyRole(ApplicationUserRole.ADMIN.name(), ApplicationUserRole.ADMINTRAINEE.name())
			.anyRequest()
			.authenticated()
			.and()
			.formLogin()
			.loginPage("/login").permitAll()
			.defaultSuccessUrl("/courses", true)
			.passwordParameter("password")
			.usernameParameter("username")
			.and()
			.rememberMe() // defaults to 2 weeks
			.tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21)).key("securekey")
			.rememberMeParameter("remember-me")
			.and()
			.logout()
			.logoutUrl("/logout")
			.clearAuthentication(true)
			.invalidateHttpSession(true)
			.deleteCookies("JSESSIONID", "remember-me")
			.logoutSuccessUrl("/login");		   
	}			

	@Override
	@Bean
	protected UserDetailsService userDetailsService() {
		UserDetails userStudent = User.builder()
								.username("user1")
								.password(passwordEncoder.encode("password"))
//								.roles(ApplicationUserRole.STUDENT.name()) // ROLE_STUDENT
								.authorities(ApplicationUserRole.STUDENT.getGrantedAuthorities())
								.build();
		
		UserDetails userAdmin = User.builder()
								.username("user2")
								.password(passwordEncoder.encode("password"))
//								.roles(ApplicationUserRole.ADMIN.name())
								.authorities(ApplicationUserRole.ADMIN.getGrantedAuthorities())
								.build();
		
		UserDetails userAdminTrainee = User.builder()
								.username("user3")
								.password(passwordEncoder.encode("password"))
//								.roles(ApplicationUserRole.ADMINTRAINEE.name())
								.authorities(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities())
								.build();
		
		return new InMemoryUserDetailsManager(userStudent, userAdmin, userAdminTrainee);
	}
}
