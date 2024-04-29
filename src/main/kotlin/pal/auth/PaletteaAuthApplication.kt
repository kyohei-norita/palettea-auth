package pal.auth

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity

@EnableWebSecurity
@SpringBootApplication
class PaletteaAuthApplication

fun main(args: Array<String>) {
    runApplication<PaletteaAuthApplication>(*args)
}
