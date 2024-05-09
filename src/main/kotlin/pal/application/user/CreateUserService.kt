package pal.application.user

import org.springframework.stereotype.Service
import pal.domain.user.User
import pal.domain.user.UserName
import pal.domain.user.UserPassword
import pal.domain.user.UserRepository

@Service
class CreateUserService(
    private val userRepository: UserRepository
) {
    fun createUser(input: CreateUserInput) {
        val user = User(
            UserName(input.username),
            UserPassword(input.password),
        )
        userRepository.save(user)
    }
}

data class CreateUserInput(
    val username: String,
    val password: String,
)