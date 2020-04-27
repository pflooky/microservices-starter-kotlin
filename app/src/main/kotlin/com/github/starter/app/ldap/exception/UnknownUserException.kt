package com.github.starter.app.ldap.exception

class UnknownUserException(user: String) : RuntimeException("User does not exist in LDAP: $user")