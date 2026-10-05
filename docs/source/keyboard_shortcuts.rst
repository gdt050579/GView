Keyboard shortcuts
==================

Every key used by GView (the main window, every viewer, the type plugins, their panels and the generic plugins) is a
named shortcut that can be listed and changed from one place: the **Keyboard shortcuts** window.

Opening the window
------------------

* Press ``F1`` in a file window, or
* use the **Help → Keyboard shortcuts** menu (it also works when no file is opened and when ``F1`` is taken by the
  operating system or by the terminal).

The window takes 80% of the screen and shows two lists:

* **Plugin & GView** (top) - the keys of the current type plugin (its commands and the keys of its panels), the commands
  of the generic plugins (Hashes, Dropper, SyncCompare, ...) and the GView keys (GoTo, Find, change viewer, ...).
* **Viewer** (bottom) - the keys of the current viewer: its commands and its *Navigation & editing* keys.

Use the **Show** box to switch between *This file* (only the keys that are active for the current file and viewer) and
*All keys* (every viewer, every generic plugin and the commands of every type plugin). Each list has its own search:
just start typing. ``Tab`` moves between the lists.

Columns
~~~~~~~

* **Key** - the key you have to press (with the current keyboard profile applied, see below).
* **Command** - the name of the shortcut (this is also the name used in the settings file).
* **Description** - what it does.
* **Status**:

  * *custom (default X)* - the key was changed by you;
  * *changed (unsaved)* - the key was changed in this window and not saved yet;
  * *Conflict: ...* - another shortcut that can be active at the same time uses the same key (only one of them works);
  * *unassigned* - the shortcut has no key;
  * *fixed* - the key is handled by a UI control (list, tree, grid) and is listed only for reference.

Changing a key
--------------

Select a shortcut and press ``Enter`` (or the **Edit** button). In the edit dialog you can:

* press the new key in the *Press the new key* field - it shows exactly what your terminal sends, which is also a quick
  way to check if a key combination reaches GView at all; or
* compose the key with the *Ctrl* / *Alt* / *Shift* boxes and the key list (useful for keys your terminal can not send,
  e.g. when preparing a configuration for another computer).

The dialog shows the default key and any conflict. **Unassign** removes the key (the command stays available from the
menus and the command bar), **Default** restores the built-in key.

Other actions: ``F3`` / **Reset** restores the default key of the selected shortcut, ``F4`` / ``Delete`` / **Unassign**
removes it, **Reset all** restores every default and the standard keyboard profile.

Nothing is applied until you press ``F2`` / **Save**. Saved keys work immediately, in every opened window. The shortcuts
of the main menus (*Windows manager*, *Exit*, *Keyboard shortcuts*) are used after GView is restarted.

Navigation keys marked *Shift extends selection* also work with ``Shift`` to extend the selection, so ``Shift`` can not be
part of their key.

Keyboard profile (Ctrl / Alt)
-----------------------------

The **Ctrl key acts as** and **Alt key acts as** boxes choose what the physical ``Ctrl`` and ``Alt`` (``Option`` on
macOS) keys mean for GView. The two possible profiles are:

* **Standard** - ``Ctrl`` is ``Ctrl`` and ``Alt`` is ``Alt`` (default on every operating system).
* **Swapped** - ``Ctrl`` acts as ``Alt`` and ``Alt`` acts as ``Ctrl``.

The profile is applied to every key (including menus, lists and dialogs) and every key label is shown as you have to
press it. The profile is stored in the ``[AppCUI]`` section (``Keyboard.Ctrl`` / ``Keyboard.Alt``).

macOS and Linux terminals
~~~~~~~~~~~~~~~~~~~~~~~~~

* ``Cmd`` is never sent to terminal applications.
* ``Option`` is sent as ``Alt`` only when the terminal is configured for it: *Terminal.app* → Settings → Profiles →
  Keyboard → **Use Option as Meta key**; *iTerm2* → Profiles → Keys → **Left Option key: Esc+**. Without it, either
  use the *Swapped* profile or the combo mode below.
* Function keys may require ``Fn`` (macOS uses some of them for system functions).
* **Combo mode**: press the backtick key (left of ``1``), then ``a`` / ``c`` / ``s`` to toggle ``Alt`` / ``Ctrl`` / ``Shift`` and finally
  the key (a letter, or ``1``-``0`` for ``F1``-``F10``). ``Space`` keeps the combo mode active, ``Escape`` leaves it.
* The command bar of a terminal only shows the commands without modifiers - use ``F1`` to see all of them.

Settings file
-------------

Only the changed keys are stored, one section per owner:

.. code-block:: ini

   [Keys.View.Buffer]
   ChangeColumnsCount = Ctrl+F6

   [Keys.Type.PE]
   DigitalSignature = Alt+F9

   [Keys.Generic.Hashes]
   Hashes = None            ; unassigned

   [AppCUI]
   Keyboard.Ctrl = Ctrl
   Keyboard.Alt  = Alt

The sections are ``Keys.GView``, ``Keys.View.<Buffer|Text|Image|Grid|Dissasm|Container|Lexical>``,
``Keys.Type.<plugin>`` and ``Keys.Generic.<plugin>``. Removing a line restores the default key. The ``Command.*``
values of the ``[Type.*]`` and ``[Generic.*]`` sections are the defaults declared by the plugins and should not be
edited. Keys stored by older versions (``Key.*`` values in ``[GView]`` and ``[View.*]``) are still read; they are moved
to the new sections the first time the shortcuts are saved.
