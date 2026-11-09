"""Security tests for F05: /grades/update lacks authentication and
role/course authorization (requirements R1, R3, R4)."""
import baseline_secure_coding_api as api


def login(client, username, password):
    response = client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert response.get_json()["user"] == username


def update(client, student_id=1001, course_id="SRS", grade=18):
    return client.post(
        "/grades/update",
        json={"student_id": student_id, "course_id": course_id, "grade": grade},
    )


def test_assigned_professor_can_update_grade(client):
    login(client, "prof_srs", "profpw")
    response = update(client)
    assert response.status_code == 200
    assert api.find_grade(1001, "SRS")["grade"] == 18


# ---- F05: authorization on /grades/update (R1, R3, R4) ----

def test_admin_can_update_any_grade(client):
    login(client, "admin1", "adminpw")
    assert update(client, 1001, "SSD", 12).status_code == 200
    assert api.find_grade(1001, "SSD")["grade"] == 12


def test_unauthenticated_update_rejected(client):
    response = update(client, grade=20)
    assert response.status_code in (401, 403)
    assert api.find_grade(1001, "SRS")["grade"] == 14


def test_student_cannot_update_own_grade(client):
    login(client, "alice", "alicepw")
    response = update(client, 1001, "SRS", 20)
    assert response.status_code == 403
    assert api.find_grade(1001, "SRS")["grade"] == 14


def test_professor_cannot_update_unassigned_course(client):
    # Variation: valid professor role, wrong course (role name alone is not enough, R4)
    login(client, "prof_srs", "profpw")
    response = update(client, 1001, "SSD", 20)
    assert response.status_code == 403
    assert api.find_grade(1001, "SSD")["grade"] == 16


def test_rejected_update_does_not_create_record(client):
    login(client, "bob", "bobpw")
    update(client, 1002, "SSD", 20)
    assert api.find_grade(1002, "SSD") is None
