package com.saml.okta.stereotypes;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;

@Service
public class SAMLUserDetailsServiceImpl implements SAMLUserDetailsService {

	@Override
	public Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {
		String username = credential.getNameID().getValue();

		System.out.println("You are logged in as "+username);
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");
		authorities.add(authority);

		return new User(username, "", true, true, true, true, authorities);
	}

}
