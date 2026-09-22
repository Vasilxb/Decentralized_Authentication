package da.decentralized_authentication.Util;

import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;

@Component
public class IdPhotoStorageService {

    private static final String UPLOAD_DIR = "uploads/id-photos";
    private static final List<String> ALLOWED_TYPES = List.of("image/jpeg", "image/png");
    private static final long MAX_SIZE = 5 * 1024 * 1024; // 5MB

    public String store(MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            throw new IllegalArgumentException("Фајлот е празен");
        }
        if (!ALLOWED_TYPES.contains(file.getContentType())) {
            throw new IllegalArgumentException("Дозволени се само JPEG или PNG слики");
        }
        if (file.getSize() > MAX_SIZE) {
            throw new IllegalArgumentException("Фајлот е преголем (макс 5MB)");
        }

        Path dir = Path.of(UPLOAD_DIR);
        Files.createDirectories(dir);

        String extension = file.getContentType().equals("image/png") ? ".png" : ".jpg";
        String filename = UUID.randomUUID() + extension; // никогаш не се верува на оригиналното име

        Path target = dir.resolve(filename);
        Files.copy(file.getInputStream(), target);

        return target.toString();
    }

    public byte[] read(String path) throws IOException {
        return Files.readAllBytes(Path.of(path));
    }
}