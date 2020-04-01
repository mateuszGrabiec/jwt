package pl.grabiecm.jwt.BookApi;

import org.springframework.web.bind.annotation.*;
import pl.grabiecm.jwt.model.Book;

import java.util.ArrayList;
import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("/api/books")
public class ApiBooks {
    private static int counter=0;
    private List<Book> bookList;

    public ApiBooks() {
        this.bookList=new ArrayList<>();
        bookList.add(new Book(counter++,"Ogniem i mieczem"));
        bookList.add(new Book(counter++,"Wesele"));
    }


    @GetMapping
    public List<Book> getBookList(){
        return bookList;
    }

    @PostMapping
    public List<Book> setBookList(@RequestBody String book){
        this.bookList.add(new Book(counter++,book));
        return this.bookList;
    }
}
