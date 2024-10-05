package edu.linus.api;

import edu.linus.api.models.EncryptedMessages;
import edu.linus.api.models.Users;
import org.springframework.data.repository.CrudRepository;

import java.util.ArrayList;
import java.util.Optional;

// This will be AUTO IMPLEMENTED by Spring into a Bean called userRepository
// CRUD refers Create, Read, Update, Delete

public interface EncryptedMessagesRepository extends CrudRepository<EncryptedMessages, Integer> {

    ArrayList<EncryptedMessages> findAllByUser(Users user);
}