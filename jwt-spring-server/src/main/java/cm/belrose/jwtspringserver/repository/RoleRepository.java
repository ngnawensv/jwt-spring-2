package cm.belrose.jwtspringserver.repository;

import cm.belrose.jwtspringserver.models.ERole;
import cm.belrose.jwtspringserver.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role,Long> {
    Optional<Role> findByName(ERole name);
}
