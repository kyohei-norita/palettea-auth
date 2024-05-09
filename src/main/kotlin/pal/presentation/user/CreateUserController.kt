package pal.presentation.user

import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import pal.application.user.CreateUserInput
import pal.application.user.CreateUserService

@RestController
class CreateUserController(
    private val createUserService: CreateUserService
) {

    @PostMapping("/user")
    fun post(@RequestBody request: CreateUserRequest) {
        val input = CreateUserInput(
            request.username,
            request.password,
        )
        createUserService.createUser(input)
    }
}

data class CreateUserRequest(
    val username: String,
    val password: String
)