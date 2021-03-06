package hibernate;

import com.google.inject.Inject;
import nl.tudelft.planningstool.database.DatabaseTestModule;
import nl.tudelft.planningstool.database.bootstrapper.BootstrapRule;
import nl.tudelft.planningstool.database.bootstrapper.TestBootstrap;
import nl.tudelft.planningstool.database.controllers.AssignmentDAO;
import nl.tudelft.planningstool.database.controllers.CourseDAO;
import nl.tudelft.planningstool.database.controllers.OccurrenceDAO;
import nl.tudelft.planningstool.database.controllers.UserDAO;
import nl.tudelft.planningstool.database.entities.User;
import nl.tudelft.planningstool.database.entities.assignments.Assignment;
import nl.tudelft.planningstool.database.entities.assignments.occurrences.Occurrence;
import nl.tudelft.planningstool.database.entities.assignments.occurrences.UserOccurrence;
import org.jukito.JukitoRunner;
import org.jukito.UseModules;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;

import javax.persistence.EntityExistsException;

import static org.junit.Assert.assertNotNull;

@RunWith(JukitoRunner.class)
@UseModules(DatabaseTestModule.class)
public class OccurrenceCreationTest {

    @Rule
    @Inject
    public BootstrapRule bootstrapRule;

    @Rule
    public ExpectedException expected = ExpectedException.none();

    @Inject
    private OccurrenceDAO occurrenceDAO;

    @Inject
    private UserDAO userDAO;

    @Inject
    private CourseDAO courseDAO;

    @Inject
    private AssignmentDAO assignmentDAO;

    @Test
    @TestBootstrap("courses/occurrences/no_occurrences.json")
    public void can_persist_occurrence() {
        UserOccurrence occurrence = new UserOccurrence();
        occurrence.setAssignment(this.assignmentDAO.getFromCourseWithId("TI1405", 2015, 1));
        occurrence.plan(1205, 5);
        occurrence.setUser(this.userDAO.getFromId(1));

        this.occurrenceDAO.persist(occurrence);
    }

    @Test
    @TestBootstrap("courses/occurrences/one_occurrence.json")
    public void can_retrieve_occurrence() {
        Assignment assignment = this.assignmentDAO.getFromCourseWithId("TI1405", 2015, 1);
        User user = this.userDAO.getFromId(1);
        Occurrence occurrence = this.occurrenceDAO.getOccurrenceForUser(user, assignment);

        assertNotNull(occurrence);
    }

    @Test
    @TestBootstrap("courses/occurrences/one_occurrence.json")
    public void can_not_persist_occurrence_for_same_course() {
        UserOccurrence occurrence = new UserOccurrence();
        occurrence.setAssignment(this.assignmentDAO.getFromCourseWithId("TI1405", 2015, 1));
        occurrence.plan(1205, 5);
        occurrence.setUser(this.userDAO.getFromId(1));
        occurrence.setId(1);

        expected.expect(EntityExistsException.class);
        this.occurrenceDAO.persist(occurrence);
    }

    @Test
    @TestBootstrap("courses/occurrences/two_courses_one_occurrence.json")
    public void can_persist_occurrence_for_different_course() {
        UserOccurrence occurrence = new UserOccurrence();
        occurrence.setAssignment(this.assignmentDAO.getFromCourseWithId("TI1505", 2015, 1));
        occurrence.plan(1205, 5);
        occurrence.setUser(this.userDAO.getFromId(1));

        this.occurrenceDAO.persist(occurrence);
    }
}
