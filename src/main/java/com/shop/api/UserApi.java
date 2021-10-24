package com.shop.api;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.validation.annotation.Validated;

import com.shop.entitty.AppRole;
import com.shop.entitty.Cart;
import com.shop.entitty.User;
import com.shop.common.ERole;
import com.shop.common.JwtUtils;
import com.shop.dto.JwtResponse;
import com.shop.dto.LoginRequest;
import com.shop.dto.MessageResponse;
import com.shop.dto.SignupRequest;
import com.shop.repository.UserRepository;
import com.shop.service.implement.UserDetailsImpl;
import com.shop.repository.CartRepository;
import com.shop.repository.AppRoleRepository;

@CrossOrigin("*")
@RestController
@RequestMapping("api/auth")
public class UserApi {
	@Autowired
	UserRepository repo;
	
	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	UserRepository userRepository;
	
	@Autowired
	CartRepository cartRepository;
	
	@Autowired
	AppRoleRepository roleRepository;

	@Autowired
	PasswordEncoder passwordEncoder;

	@Autowired
	JwtUtils jwtUtils;
	
	@GetMapping
	public ResponseEntity<List<User>> getAll() {
		return ResponseEntity.ok(repo.findAll());
	}
	
	@GetMapping("{id}")
	public ResponseEntity<User> getOne(@PathVariable("id") Long id) {
		if(!repo.existsById(id)) {
			return ResponseEntity.notFound().build();
		}
		return ResponseEntity.ok(repo.findById(id).get());
	}
	
	@GetMapping("email/{email}")
	public ResponseEntity<Optional<User>> getOneByEmail(@PathVariable("email") String email) {
		if(repo.existsByEmail(email)) {			
			return ResponseEntity.ok(repo.findByEmail(email));
		}
		return ResponseEntity.notFound().build();
	}
	
//	@PostMapping
//	public ResponseEntity<User> post(@RequestBody User user) {
//		if(repo.existsByEmail(user.getEmail())) {
//			return ResponseEntity.notFound().build();
//		}
//		if(repo.existsById(user.getUserId())) {
//			return ResponseEntity.badRequest().build();
//		}
//
//		User u =  repo.save(user);
//		Cart c = new Cart(0L, 0.0, u.getAddress(), u.getPhone(), u);
//		cartRepository.save(c);
//		return ResponseEntity.ok(u);
//	}
	
	@PutMapping("{id}")
	public ResponseEntity<User> put(@PathVariable("id") Long id, @RequestBody User user) {
		if(!repo.existsById(id)) {
			return ResponseEntity.notFound().build();
		}
		if(!id.equals(user.getUserId())) {
			return ResponseEntity.badRequest().build();
		}
		
		return ResponseEntity.ok(repo.save(user));
	}
	
	@PutMapping("admin/{id}")
	public ResponseEntity<User> putAdmin(@PathVariable("id") Long id, @RequestBody User user) {
		if(!repo.existsById(id)) {
			return ResponseEntity.notFound().build();
		}
		if(!id.equals(user.getUserId())) {
			return ResponseEntity.badRequest().build();
		}
		return ResponseEntity.ok(repo.save(user));
	}
	
	@DeleteMapping("{id}")
	public ResponseEntity<Void> delete(@PathVariable("id") Long id) {
		if(!repo.existsById(id)) {
			return ResponseEntity.notFound().build();
		}
		User u = repo.findById(id).get();
		u.setStatus(false);
		repo.save(u);
//		repo.deleteById(id);
		return ResponseEntity.ok().build();
	}
	
	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Validated @RequestBody LoginRequest loginRequest) {

		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(authentication);
		String jwt = jwtUtils.generateJwtToken(authentication);

		UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
		List<String> roles = userDetails.getAuthorities().stream()
				.map(item -> item.getAuthority())
				.collect(Collectors.toList());
		
		return ResponseEntity.ok(new JwtResponse(
												jwt,
												userDetails.getId(),
												userDetails.getName(),
												userDetails.getEmail(),
												userDetails.getPassword(),
												userDetails.getPhone(),
												userDetails.getAddress(),
												userDetails.getGender(),
												userDetails.getStatus(),
												userDetails.getImage(),
												userDetails.getRegisterDate(),
												roles));
		
	}

	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Validated @RequestBody SignupRequest signupRequest) {

		if (userRepository.existsByEmail(signupRequest.getEmail())) {
			return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already taken!"));

		}

		if (userRepository.existsByEmail(signupRequest.getEmail())) {

			return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is alreadv in use!"));

		}

		// create new user account
		User user = new User(signupRequest.getName(), signupRequest.getEmail(),
				passwordEncoder.encode(signupRequest.getPassword()) ,signupRequest.getPhone(),signupRequest.getAddress(),
				signupRequest.getGender(),signupRequest.getStatus(),signupRequest.getImage(),signupRequest.getRegisterDate());

		Set<String> strRoles = signupRequest.getRole();
		Set<AppRole> roles = new HashSet<>();

		if (strRoles == null) {
			AppRole userRole = roleRepository.findByName(ERole.ROLE_USER)
					.orElseThrow(() -> new RuntimeException("Error: Role is not found."));

			roles.add(userRole);

		} else {
			strRoles.forEach(role -> {
				switch (role) {
				case "admin":
					AppRole adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));

					roles.add(adminRole);
					break;


				default:
					AppRole userRole = roleRepository.findByName(ERole.ROLE_USER)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));

					roles.add(userRole);

				}
			});
		}

		user.setRoles(roles);
		userRepository.save(user);
		Cart c = new Cart(0L, 0.0, user.getAddress(), user.getPhone(), user);
		cartRepository.save(c);
		return ResponseEntity.ok(new MessageResponse("Đăng kí thành công"));

	}
}
