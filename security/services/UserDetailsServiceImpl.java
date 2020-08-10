package com.sailotech.tm.security.services;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sailotech.tm.dao.AdminDAO;
import com.sailotech.tm.dao.PatientDAO;
import com.sailotech.tm.dao.PhysicianDAO;
import com.sailotech.tm.dao.SecurityUserDetails;
import com.sailotech.tm.dao.UserRole;
import com.sailotech.tm.repository.AdminRepository;
import com.sailotech.tm.repository.PatientRepository;
import com.sailotech.tm.repository.PhysicianRepository;
import com.sailotech.tm.security.jwt.UserType;
import com.sailotech.tm.util.Constants;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

	@Autowired
	private PatientRepository patientRepository;

	@Autowired
	private PhysicianRepository physicianRepository;
	
	@Autowired
	private AdminRepository adminRepository;

	@Override
	@Transactional(readOnly = true)
	public UserDetails loadUserByUsername(String username) {
		
		 String[] usernameAndDomain = StringUtils.split(
		          username,Constants.SPLIT_VARIABLE);
		 SecurityUserDetails sec = null;
		if( UserType.PH.toString().equals(usernameAndDomain[1])) {
			PhysicianDAO phy;
			if (usernameAndDomain[0].contains("@")) {
				phy = physicianRepository.findByEmail(usernameAndDomain[0]);
			} else {
				phy = physicianRepository.findByDoctorId(usernameAndDomain[0]);
			}
			if(phy!=null) {
				if(!phy.isAdminVerified())
					throw new UsernameNotFoundException("User Login Disabled");

				sec = new SecurityUserDetails(phy.getName(), phy.getPassword(), getAuthorities(phy.getRole()),phy);
				
			}
			
		}else if( UserType.PT.toString().equals(usernameAndDomain[1])) {
			PatientDAO patient;
			if (usernameAndDomain[0].contains("@")) {
				patient =patientRepository.findByEmailAndAllowLogin(usernameAndDomain[0],true);
			} else {
				patient =patientRepository.findByPatientIdAndAllowLogin(usernameAndDomain[0],true);
			}
			if(patient!=null)
				sec = new SecurityUserDetails(patient.getName(), patient.getPassword(), getAuthorities(patient.getRole()),patient);
		}else if( UserType.AD.toString().equals(usernameAndDomain[1])) {
			AdminDAO admin= adminRepository.findByLoginId(usernameAndDomain[0]);
			if(admin!=null)
				sec = new SecurityUserDetails(admin.getLoginId(), admin.getPassword(), getAuthorities(admin.getRole()),admin);
		}
		if (sec == null) {
			throw new UsernameNotFoundException(usernameAndDomain[0]);
		}
		return sec;
	}

	public List<GrantedAuthority> getAuthorities(UserRole role) {
		List<GrantedAuthority> authorities = new ArrayList<>();
		authorities.add(new SimpleGrantedAuthority(role.getRoleName()));
		return authorities;
	}

}
