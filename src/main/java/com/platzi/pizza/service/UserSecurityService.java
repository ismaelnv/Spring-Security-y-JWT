package com.platzi.pizza.service;

import com.platzi.pizza.persitence.entity.UserEntity;
import com.platzi.pizza.persitence.entity.UserRoleEntity;
import com.platzi.pizza.persitence.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class UserSecurityService implements UserDetailsService {

    private final UserRepository _userRepository;

    @Autowired
    public UserSecurityService(UserRepository userRepository) {

        _userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserEntity userEntity = this._userRepository.findById(username)
                .orElseThrow(() -> new UsernameNotFoundException("user "+username+" not fount."));

        //consegir un arreglo de roles de tipo string
        String[] roles = userEntity.getRoles().stream().map(UserRoleEntity::getRole).toArray(String[]::new);

        return User.builder()
                .username(userEntity.getUsername())
                .password(userEntity.getPassword())
                .authorities(this.grantedAuthorities(roles))
                .accountLocked(userEntity.getLocked())
                .disabled(userEntity.getDisabled())
                .build();
    }

    private String[] getAuthorities(String role){

        if ("ADMIN".equals(role) || "CUSTOMER".equals(role)){

            return new String[]{"random_order"};
        }
        if ("COCINERO".equals(role)){

            return new String[]{"random_cocinero"};
        }


        return  new String[]{};
    }

    private List<GrantedAuthority> grantedAuthorities(String[] roles){

        List<GrantedAuthority> authorities = new ArrayList<>(roles.length);

        for (String role: roles){

            authorities.add(new SimpleGrantedAuthority("ROLE_"+role));

            for (String authority: this.getAuthorities(role)){

                authorities.add( new SimpleGrantedAuthority(authority));
            }
        }

        return authorities;
    }
}
