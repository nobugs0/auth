//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.NoBugs.cognito_login.authentication;

import java.util.List;

public interface UserRepositoryImplementation<T extends User> {
    T update(T model);

    T save(T model);

    List<T> findAll();

    T findByEmail(String email);

    T findBySub(String sub);
}
