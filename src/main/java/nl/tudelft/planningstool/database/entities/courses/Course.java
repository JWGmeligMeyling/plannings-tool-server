package nl.tudelft.planningstool.database.entities.courses;

import lombok.Data;
import lombok.EqualsAndHashCode;
import nl.tudelft.planningstool.database.entities.assignments.Assignment;

import javax.persistence.*;
import java.util.Set;

@Data
@Entity
@Table(name = "courses")
@EqualsAndHashCode(of = {
        "edition"
})
public class Course {

    @EmbeddedId
    private CourseEdition edition;

    @OneToMany(mappedBy = "course")
    private Set<CourseRelation> users;

    @OneToMany(mappedBy = "course")
    private Set<Assignment> assignments;

    @Column(name = "examTime")
    private long examTime;

    public void addAssignment(Assignment assignment) {
        assignment.setId(this.getAssignments().size() + 1);

        this.getAssignments().add(assignment);
    }
}
