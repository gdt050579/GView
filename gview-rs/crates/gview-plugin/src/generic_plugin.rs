//! Native generic-plugin contract (spec `03_DUAL_PLUGIN` §3.5, §6.1;
//! C++ `.gpl` exports `Run(command, Reference<Object>)` and
//! `UpdateSettings(IniSection)`).
//!
//! A generic plugin is a command provider that acts on the current
//! [`Object`] (hashes, entropy, …). Its `UpdateSettings` only writes
//! `Command.<name> = <key>` entries (plus an optional description),
//! captured here as [`GenericPluginMetadata`]; the host binds every
//! command's key and calls [`GenericPlugin::run`] with the short
//! command name from the INI key.
//!
//! `run` receives the object mutably: the C++ passes a mutable
//! `Reference<Object>` and every read goes through `DataCache::Get`,
//! which is `&mut self` in the Rust port.

use gview_core::object::Object;

use crate::type_plugin::{CommandDef, PluginError};

/// C++ generic `UpdateSettings` output.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GenericPluginMetadata {
    /// `Description` (optional in C++; empty when absent).
    pub description: String,
    /// `Command.<name>` entries.
    pub commands: Vec<CommandDef>,
}

impl GenericPluginMetadata {
    /// Finds a command by its INI short name.
    #[must_use]
    pub fn command(&self, name: &str) -> Option<&CommandDef> {
        self.commands.iter().find(|c| c.name == name)
    }
}

/// The native generic plugin (spec §6.1).
pub trait GenericPlugin: Send + Sync {
    /// Plugin name (`Generic.<Name>` section, `.gpl` file stem).
    fn name(&self) -> &'static str;

    /// `UpdateSettings` export.
    fn metadata() -> GenericPluginMetadata
    where
        Self: Sized;

    /// `Run(command, object)` export: `command` is the `Command.<name>`
    /// suffix.
    ///
    /// # Errors
    ///
    /// [`PluginError::UnknownCommand`] for a name the plugin does not
    /// provide; any other [`PluginError`] the command raises.
    fn run(&self, command: &str, object: &mut Object) -> Result<(), PluginError>;
}

/// Function-pointer view of a [`GenericPlugin`] implementation.
#[derive(Clone, Copy)]
pub struct GenericPluginDescriptor {
    /// Plugin name.
    pub name: &'static str,
    /// `UpdateSettings` export.
    pub metadata: fn() -> GenericPluginMetadata,
    /// Instance factory (generic plugins are stateless in C++; the
    /// host keeps one instance).
    pub create: fn() -> Box<dyn GenericPlugin>,
}

impl core::fmt::Debug for GenericPluginDescriptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GenericPluginDescriptor")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl GenericPluginDescriptor {
    /// Describes plugin type `P` under `name`.
    #[must_use]
    pub fn of<P: GenericPlugin + Default + 'static>(name: &'static str) -> Self {
        Self {
            name,
            metadata: P::metadata,
            create: || Box::new(P::default()),
        }
    }
}

/// One registered generic plugin: its instance plus metadata.
pub struct RegisteredGenericPlugin {
    descriptor: GenericPluginDescriptor,
    metadata: GenericPluginMetadata,
    instance: Box<dyn GenericPlugin>,
}

impl core::fmt::Debug for RegisteredGenericPlugin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RegisteredGenericPlugin")
            .field("name", &self.descriptor.name)
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}

impl RegisteredGenericPlugin {
    /// Plugin name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.descriptor.name
    }

    /// The metadata as declared.
    #[must_use]
    pub const fn metadata(&self) -> &GenericPluginMetadata {
        &self.metadata
    }

    /// The live instance.
    #[must_use]
    pub fn instance(&self) -> &dyn GenericPlugin {
        self.instance.as_ref()
    }

    /// Runs `command` on `object` if the plugin declares it
    /// (the host's `Command.<name>` dispatch).
    ///
    /// # Errors
    ///
    /// [`PluginError::UnknownCommand`] when the plugin's metadata does
    /// not declare `command`; otherwise whatever `run` returns.
    pub fn run(&self, command: &str, object: &mut Object) -> Result<(), PluginError> {
        if self.metadata.command(command).is_none() {
            return Err(PluginError::UnknownCommand(command.to_owned()));
        }
        self.instance.run(command, object)
    }
}

/// The host's generic-plugin table (C++ `Instance::genericPlugins`),
/// in registration order.
#[derive(Debug, Default)]
pub struct GenericPluginRegistry {
    plugins: Vec<RegisteredGenericPlugin>,
}

impl GenericPluginRegistry {
    /// An empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self { plugins: Vec::new() }
    }

    /// Registers a plugin, instantiating it once.
    ///
    /// # Errors
    ///
    /// [`PluginError::DuplicateName`].
    pub fn register(&mut self, descriptor: GenericPluginDescriptor) -> Result<(), PluginError> {
        if self.plugins.iter().any(|p| p.name() == descriptor.name) {
            return Err(PluginError::DuplicateName(descriptor.name.to_owned()));
        }
        self.plugins.push(RegisteredGenericPlugin {
            descriptor,
            metadata: (descriptor.metadata)(),
            instance: (descriptor.create)(),
        });
        Ok(())
    }

    /// Registers plugin type `P` under `name`.
    ///
    /// # Errors
    ///
    /// As [`Self::register`].
    pub fn register_type<P: GenericPlugin + Default + 'static>(&mut self, name: &'static str) -> Result<(), PluginError> {
        self.register(GenericPluginDescriptor::of::<P>(name))
    }

    /// Registered plugins.
    #[must_use]
    pub fn plugins(&self) -> &[RegisteredGenericPlugin] {
        &self.plugins
    }

    /// Lookup by name.
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&RegisteredGenericPlugin> {
        self.plugins.iter().find(|p| p.name() == name)
    }

    /// Number of registered plugins.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.plugins.len()
    }

    /// `true` when nothing is registered.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// Finds the plugin (and command) bound to `key`
    /// (the command-bar / hot-key dispatch).
    #[must_use]
    pub fn command_for_key(&self, key: appcui::input::Key) -> Option<(&RegisteredGenericPlugin, &CommandDef)> {
        self.plugins.iter().find_map(|p| {
            p.metadata()
                .commands
                .iter()
                .find(|c| c.key == key)
                .map(|c| (p, c))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use appcui::input::{Key, KeyCode, KeyModifier};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[derive(Default)]
    struct Hashes {
        runs: Arc<AtomicUsize>,
    }

    impl GenericPlugin for Hashes {
        fn name(&self) -> &'static str {
            "Hashes"
        }
        fn metadata() -> GenericPluginMetadata {
            GenericPluginMetadata {
                description: String::from("Compute hashes"),
                commands: vec![CommandDef::new(
                    "Hashes",
                    Key::new(KeyCode::F5, KeyModifier::Ctrl),
                    "Compute hashes for the current object",
                    0,
                )],
            }
        }
        fn run(&self, command: &str, object: &mut Object) -> Result<(), PluginError> {
            if command != "Hashes" {
                return Err(PluginError::UnknownCommand(command.to_owned()));
            }
            // Touch the object the way a real plugin would.
            let size = object.data().size();
            if size == 0 {
                return Err(PluginError::Unsupported(String::from("empty object")));
            }
            self.runs.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn generic_plugin_is_send_sync_and_runs_commands() {
        assert_send_sync::<Hashes>();
        assert_send_sync::<Box<dyn GenericPlugin>>();

        let mut registry = GenericPluginRegistry::new();
        registry.register_type::<Hashes>("Hashes").expect("register");
        assert_eq!(registry.len(), 1);
        assert!(!registry.is_empty());
        let plugin = registry.by_name("Hashes").expect("plugin");
        assert_eq!(plugin.name(), "Hashes");
        assert_eq!(plugin.instance().name(), "Hashes");
        assert_eq!(plugin.metadata().description, "Compute hashes");

        let mut object = Object::from_buffer(b"data", "t", 0);
        plugin.run("Hashes", &mut object).expect("run");
        assert!(matches!(
            plugin.run("Nope", &mut object),
            Err(PluginError::UnknownCommand(_))
        ));
        let mut empty = Object::from_buffer(b"", "e", 0);
        assert!(matches!(
            plugin.run("Hashes", &mut empty),
            Err(PluginError::Unsupported(_))
        ));
    }

    #[test]
    fn duplicate_names_are_rejected_and_keys_dispatch() {
        let mut registry = GenericPluginRegistry::new();
        registry.register_type::<Hashes>("Hashes").expect("register");
        assert_eq!(
            registry.register_type::<Hashes>("Hashes"),
            Err(PluginError::DuplicateName(String::from("Hashes")))
        );
        let (plugin, command) = registry
            .command_for_key(Key::new(KeyCode::F5, KeyModifier::Ctrl))
            .expect("bound");
        assert_eq!(plugin.name(), "Hashes");
        assert_eq!(command.name, "Hashes");
        assert!(registry
            .command_for_key(Key::new(KeyCode::F6, KeyModifier::Ctrl))
            .is_none());
        assert!(format!("{:?}", registry.plugins()[0]).contains("Hashes"));
    }
}
