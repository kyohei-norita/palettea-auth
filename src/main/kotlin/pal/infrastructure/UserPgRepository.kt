package pal.infrastructure

import org.springframework.stereotype.Repository
import pal.domain.user.User
import pal.domain.user.UserRepository

@Repository
class UserPgRepository(
    private val userMapper: UserMapper
): UserRepository {

    override fun save(user: User) {
        val inputRecord = UserInsertRecord(
            user.name.value,
            user.password.value
        )
        userMapper.insert(inputRecord)
    }
}