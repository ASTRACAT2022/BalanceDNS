# Руководство по созданию плагинов

Этот документ описывает, как создавать плагины для расширения функциональности DNS-резолвера.

## Архитектура плагинов

Плагины позволяют добавлять пользовательскую логику в процесс обработки DNS-запросов. Они могут быть использованы для мониторинга, фильтрации или изменения запросов и ответов.

Система плагинов состоит из следующих компонентов:

- **Plugin Interface**: `internal/plugins/plugins.go`
  - `Name() string`: Возвращает имя плагина.
  - `Execute(*PluginContext, *dns.Msg) error`: Выполняет логику плагина.
- **PluginManager**: `internal/plugins/plugins.go`
  - `Register(Plugin)`: Регистрирует новый плагин.
  - `ExecutePlugins(*PluginContext, *dns.Msg)`: Выполняет все зарегистрированные плагины.

## Как создать плагин

1. **Создайте новую директорию для вашего плагина** в директории `plugins/`. Например, `plugins/my_plugin`.

2. **Создайте файл .go** в этой директории. Например, `plugins/my_plugin/my_plugin.go`.

3. **Реализуйте интерфейс `Plugin`**:

   ```go
   package my_plugin

   import (
       "log"

       "dns-resolver/internal/plugins"
       "github.com/miekg/dns"
   )

   type MyPlugin struct{}

   func (p *MyPlugin) Name() string {
       return "MyPlugin"
   }

   func (p *MyPlugin) Execute(ctx *plugins.PluginContext, msg *dns.Msg) error {
       // Ваша логика здесь
       log.Printf("[%s] Обработка запроса: %s", p.Name(), msg.Question[0].Name)
       return nil
   }

   func New() *MyPlugin {
       return &MyPlugin{}
   }
   ```

4. **Зарегистрируйте ваш плагин** в `main.go`:

   ```go
   import (
       // ...
       "dns-resolver/plugins/my_plugin"
   )

   func main() {
       // ...
       pm := plugins.NewPluginManager()

       myPlugin := my_plugin.New()
       pm.Register(myPlugin)

       // ...
   }
   ```

## Пример плагина

Пример плагина, который логирует все DNS-запросы, можно найти в `plugins/example_logger`.