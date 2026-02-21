---
description: 'Guidelines for building Spring Boot base applications'
applyTo: '**/*.java, **/*.kt'
---

# Spring Boot Development

## General Instructions

- Make only high confidence suggestions when reviewing code changes.
- Write code with good maintainability practices, including comments on why certain design decisions were made.
- Handle edge cases and write clear exception handling.
- For libraries or external dependencies, mention their usage and purpose in comments.

## Spring Boot Instructions

### Dependency Injection

- **Always use constructor injection** for all required dependencies.
- **Use Lombok `@RequiredArgsConstructor`** to auto-generate constructors for `final` fields.
- Declare dependency fields as `private final`.
- **Migration Note**: This project is transitioning from field injection (`@Autowired`) to constructor injection.

### Lombok Best Practices

- Prefer focused Lombok annotations (`@Getter`, `@Setter`, `@ToString`, `@EqualsAndHashCode`) over `@Data` when you need tighter control.
- For JPA entities, avoid `@EqualsAndHashCode` on mutable fields and be cautious with `@ToString` on lazy-loaded relationships (use `@ToString.Exclude`).
- Use `@Builder` for complex object creation, but keep it off JPA entities unless you also provide required constructors.
- Use `@Slf4j` for logging instead of manual logger declarations.
- Keep Lombok annotations on classes only when they reduce noise; do not add them if they obscure logic or intent.

### Configuration

- Use YAML files (`application.yml`) for externalized configuration.
- Environment Profiles: Use Spring profiles for different environments (dev, test, prod)
- Configuration Properties: Use @ConfigurationProperties for type-safe configuration binding
- Secrets Management: Externalize secrets using environment variables or secret management systems

### Code Organization

- **Package Structure**: Organize by feature/domain rather than by layer
  - **Target Structure**: `com.dinkybell.ecommerce.{feature}.{layer}`
  - **Examples**: `com.dinkybell.ecommerce.authentication.*`, `com.dinkybell.ecommerce.order.*`
  - **Migration Note**: Currently migrating from layer-based to feature-based organization
- **Separation of Concerns**: Keep controllers thin, services focused, and repositories simple
- **Utility Classes**: Make utility classes final with private constructors

### Service Layer

- Place business logic in `@Service`-annotated classes.
- Services should be stateless and testable.
- Inject repositories via the constructor.
- Service method signatures should use domain IDs or DTOs, not expose repository entities directly unless necessary.

### Logging

- Use SLF4J for all logging (`private static final Logger logger = LoggerFactory.getLogger(MyClass.class);`).
- Do not use concrete implementations (Logback, Log4j2) or `System.out.println()` directly.
- Use parameterized logging: `logger.info("User {} logged in", userId);`.

### Security & Input Handling

- Use parameterized queries | Always use Spring Data JPA or `NamedParameterJdbcTemplate` to prevent SQL injection.
- Validate request bodies and parameters using JSR-380 (`@NotNull`, `@Size`, etc.) annotations and `BindingResult`

## Build and Verification

- After adding or modifying code, verify the project continues to build successfully.
- **Dinkybell Project**: Use `./mvnw clean install` for full build
- **Dinkybell Project**: Use `source ./setenv.sh` to load environment variables before running
- Ensure all tests pass as part of the build.

## Project-Specific Notes

For Dinkybell-specific patterns and architecture details, refer to `.github/copilot-instructions.md` which documents:
- JWT + Refresh Token authentication flow
- Device fingerprinting and multi-session management  
- Custom rate limiting implementation
- Argon2id password hashing
- Security and debugging patterns
