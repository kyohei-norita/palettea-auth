package pal.infrastructure

import org.apache.ibatis.annotations.Insert
import org.apache.ibatis.annotations.Mapper

@Mapper
interface UserMapper {

    @Insert("""
        INSERT INTO pal_auth.users (username, password) 
        VALUES (#{input.username}, #{input.password})
        """)
    fun insert(input: UserInsertRecord)
}

data class UserInsertRecord(
    val username: String,
    val password: String,
)