package com.saml.okta.controller;

import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import com.saml.okta.stereotypes.CurrentUser;

@Controller
public class IndexController {

	@Autowired
	private MetadataManager metadata;
	
	@RequestMapping("/")
	 public String index(@CurrentUser User user, Model model) {
    	Set<String> idps = metadata.getIDPEntityNames();
		for (String idp : idps)
			System.out.println("Configured Identity Provider for SSO: " + idp);
		
		model.addAttribute("username", 	user.getUsername());
        return "index";
    }

}