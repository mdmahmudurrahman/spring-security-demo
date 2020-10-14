package com.amigoscode.ssecurity.ssapp.student;

import java.util.Arrays;
import java.util.List;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {
	private static final List<Student> students = Arrays.asList(
		new Student(1, "AAA"),
		new Student(2, "BBB"),
		new Student(3, "CCC")
	);

	@GetMapping
	public List<Student> getAllStudents() {
		return students;
	}
	
	@PostMapping
	public void registerNewStudent(Student student) {
		System.out.println(student);
	}
	
	@DeleteMapping(path = "{studentId}")
	public void deleteStudent(@PathVariable("studentId") Integer studentId) {
		System.out.println(studentId);
	}
	
	@PutMapping(path = "{studentId}")
	public void updateStudent(@PathVariable("studentId") Integer studentId, Student student) {
		System.out.println(student);
	}
}