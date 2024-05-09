package pal.domain.user

data class User(
    val name: UserName,
    val password: UserPassword
)

@JvmInline
value class UserName(val value: String) {}

@JvmInline
value class UserPassword(val value: String) {}

interface UserRepository {
    fun save(user: User)
}