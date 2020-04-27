package com.github.starter.app.ldap.service

import com.github.starter.app.config.LdapConfig
import com.github.starter.app.ldap.exception.UnknownUserException
import org.apache.directory.api.ldap.model.cursor.EntryCursor
import org.apache.directory.api.ldap.model.entry.DefaultEntry
import org.apache.directory.api.ldap.model.entry.Entry
import org.apache.directory.api.ldap.model.message.SearchScope
import org.apache.directory.ldap.client.api.LdapConnection
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.Mockito
import org.springframework.test.context.junit.jupiter.SpringExtension
import java.lang.RuntimeException

@DisplayName("Ldap Service Test")
@ExtendWith(SpringExtension::class)
internal class DefaultLdapServiceTest {

    private val ldapConnection: LdapConnection = Mockito.mock(LdapConnection::class.java)
    private val entryCursor: EntryCursor = Mockito.mock(EntryCursor::class.java)
    private val ldapConfig: LdapConfig = LdapConfig()
    private val ldapService: LdapService
    private val entry: Entry
    private val baseDn = "dc=example,dc=org"

    init {
        ldapConfig.baseDn = baseDn
        ldapService = DefaultLdapService(ldapConnection, ldapConfig)
        entry = DefaultEntry(baseDn, "cn:admin", "sAMAccountName:admin", "description:The admin")
    }

    @BeforeEach
    private fun createLdapBase() {
        Mockito.`when`(entryCursor.iterator())
                .thenReturn(mutableListOf<Entry>(
                        DefaultEntry(baseDn, "cn:admin", "sAMAccountName:admin", "description:The admin"),
                        DefaultEntry(baseDn, "cn:admin", "sAMAccountName:fred", "description:The admin's best friend")
                ).iterator())
        Mockito.`when`(ldapConnection.search(Mockito.matches(baseDn), Mockito.anyString(), Mockito.any(SearchScope::class.java)))
                .thenReturn(entryCursor)
    }

    @Test
    fun `test get members list`() {
        //when
        val result = ldapService.checkMembers("admin")

        //then
        result.subscribe {
            assertEquals(2, it.size)
            assertEquals(it, listOf("admin", "fred"))
        }.dispose()
    }

    @Test
    fun `get attribute of a user`() {
        //when
        val result = ldapService.getAttribute("admin", "description")

        //then
        result.subscribe {
            assertTrue(it.isNotEmpty())
            assertEquals("The admin", it)
        }.dispose()
    }

    @Test
    fun `try get attribute of a user that doesn't exist`() {
        //when
        Mockito.`when`(entryCursor.iterator())
                .thenReturn(mutableListOf<Entry>().iterator())

        //then
        assertThrows<UnknownUserException> {
            ldapService.getAttribute("peter", "description").block()
        }
    }
}