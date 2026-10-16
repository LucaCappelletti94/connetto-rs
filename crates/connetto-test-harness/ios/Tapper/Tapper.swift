import XCTest

/// One error the tapper names in the test log the proof keeps.
enum TapperError: LocalizedError {
    case action(String)

    var errorDescription: String? {
        switch self {
        case .action(let message): message
        }
    }
}

/// Taps a system alert with a known button, or switches Personal Hotspot in
/// Settings, one action per start. The action and its arguments arrive as
/// `TEST_RUNNER_` environment variables the proof writes into the run's
/// xctestrun file, since a shell environment does not cross from the Mac to
/// the device.
final class TapperTests: XCTestCase {
    /// The demo the tapper returns to after a Settings action.
    static let demoBundle = "dev.connetto.dioxusdemo"

    func testAction() throws {
        let environment = ProcessInfo.processInfo.environment
        let bound = bounded(environment["TEST_RUNNER_TIMEOUT"], default: 90)
        switch environment["TEST_RUNNER_ACTION"] ?? "" {
        case "tap-alert":
            let labels = labels(environment["TEST_RUNNER_LABELS"])
            guard !labels.isEmpty else {
                throw TapperError.action("TEST_RUNNER_LABELS names no button")
            }
            try tapAlert(labels: labels, bound: bound)
        case "hotspot-on", "hotspot-off":
            try personalHotspot(on: environment["TEST_RUNNER_ACTION"] == "hotspot-on", bound: bound)
        default:
            throw TapperError.action(
                "no TEST_RUNNER_ACTION, or an unknown one: \(environment["TEST_RUNNER_ACTION"] ?? "")"
            )
        }
    }

    /// The bound in seconds, clamped so a bad value cannot hang the run.
    private func bounded(_ raw: String?, default defaultValue: TimeInterval) -> TimeInterval {
        let value = raw.flatMap(TimeInterval.init) ?? defaultValue
        return min(max(value, 5), 600)
    }

    private func labels(_ raw: String?) -> [String] {
        (raw ?? "")
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    /// Tap an alert with a known button as long as such an alert shows, so a
    /// join and a local-network prompt in one join are both cleared. The
    /// action holds a floor, since it can start before its trigger, and
    /// quits on the silence after the last alert, since a prompt appears
    /// within a couple of seconds of its trigger.
    private func tapAlert(labels: [String], bound: TimeInterval) throws {
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        let deadline = Date().addingTimeInterval(bound)
        let floor = min(bound, 10)
        let quiet: TimeInterval = 8
        let started = Date()
        var lastAlert = Date.distantPast
        var taps = 0
        var seen = "no alert"
        while Date() < deadline {
            let alert = springboard.alerts.element
            if alert.exists {
                lastAlert = Date()
                // The alert can go at any point between the look and the tap,
                // answered by its own timeout, by the system or by a person
                // at the phone, which leaves nothing to tap and nothing wrong.
                let options = XCTExpectedFailure.Options()
                options.isStrict = false
                XCTExpectFailure("the alert went before its tap", options: options) {
                    // The label is read before the tap, since the alert is
                    // gone after it.
                    let label = alert.label
                    seen = "the alert \(label) with \(alert.buttons.count) button(s)"
                    if let match = labels.first(where: { alert.buttons[$0].firstMatch.exists }) {
                        alert.buttons[match].firstMatch.tap()
                        taps += 1
                        print("tapped \(match) on the alert: \(label)")
                    }
                }
            }
            Thread.sleep(forTimeInterval: 0.5)
            if Date().timeIntervalSince(started) > floor, Date().timeIntervalSince(lastAlert) > quiet {
                break
            }
        }
        if springboard.alerts.element.exists {
            throw TapperError.action("an alert stayed after \(Int(bound))s: \(seen)")
        }
        print(taps == 0 ? "no alert to tap" : "tapped \(taps) alert(s)")
    }

    /// The Personal Hotspot row's title in the languages the proof's phones
    /// run.
    static let paneTitles = ["Hotspot personale", "Personal Hotspot"]
    /// The pane's switch that lets other devices join, in the same languages.
    static let joinSwitches = ["Consenti agli altri di accedere", "Allow Others to Join"]

    /// Switch Personal Hotspot on or off in Settings and return to the demo.
    /// A switch whose value reads as the wanted state is left alone, and the
    /// value is read again after a tap.
    private func personalHotspot(on: Bool, bound: TimeInterval) throws {
        let settings = XCUIApplication(bundleIdentifier: "com.apple.Preferences")
        let toggle = try openPersonalHotspotPane(settings, bound: bound)
        let wanted = on ? "1" : "0"
        if let value = toggle.value as? String, value == wanted {
            print("Personal Hotspot already \(on ? "on" : "off")")
        } else {
            let knob = toggle.switches.firstMatch
            (knob.exists && knob.isHittable ? knob : toggle).tap()
            Thread.sleep(forTimeInterval: 1)
            if let value = toggle.value as? String, value != wanted {
                throw TapperError.action("the switch reads \(value) after the tap, wanted \(wanted)")
            }
            print("Personal Hotspot switched \(on ? "on" : "off")")
        }
        try returnToDemo()
    }

    /// Open the pane from the row that names it, on Settings' top list or
    /// else among the search results, and answer its join switch, whose
    /// appearance is what says the pane opened. Only a hittable row counts,
    /// since the top list's row stays in the hierarchy under the search
    /// results.
    private func openPersonalHotspotPane(_ settings: XCUIApplication, bound: TimeInterval) throws -> XCUIElement {
        let deadline = Date().addingTimeInterval(min(bound, 60))
        let join = settings.switches
            .matching(NSPredicate(format: "identifier IN %@", Self.joinSwitches))
            .firstMatch
        for title in Self.paneTitles {
            settings.terminate()
            settings.launch()
            guard settings.windows.firstMatch.waitForExistence(timeout: 10) else {
                throw TapperError.action("Settings never opened")
            }
            var row = hittableRow(settings, title: title, within: 5)
            if row == nil {
                let search = settings.searchFields.firstMatch
                guard search.waitForExistence(timeout: 10) else {
                    throw TapperError.action("no search field in Settings")
                }
                search.tap()
                search.typeText(title)
                row = hittableRow(settings, title: title, within: 5)
            }
            if let row {
                row.tap()
                if join.waitForExistence(timeout: 10) {
                    print("the \(title) pane opened")
                    return join
                }
            }
            print("no row named \(title) opened its pane, the screen shows:\n\(settings.debugDescription)")
            guard Date() < deadline else { break }
        }
        throw TapperError.action("the Personal Hotspot pane never opened, searched for \(Self.paneTitles)")
    }

    /// The first hittable cell holding `title`, polled until `within` passes.
    private func hittableRow(_ settings: XCUIApplication, title: String, within: TimeInterval) -> XCUIElement? {
        let deadline = Date().addingTimeInterval(within)
        repeat {
            let rows = settings.cells
                .containing(NSPredicate(format: "label ==[c] %@", title))
                .allElementsBoundByIndex
            if let row = rows.first(where: { $0.exists && $0.isHittable }) {
                return row
            }
            Thread.sleep(forTimeInterval: 0.5)
        } while Date() < deadline
        return nil
    }

    /// Bring the demo back to the front, where the proof drives its page.
    /// It is activated, never launched, since a launch would restart it
    /// without the environment the proof started it with, and a demo that is
    /// not running stays so.
    private func returnToDemo() throws {
        let demo = XCUIApplication(bundleIdentifier: Self.demoBundle)
        guard demo.state != .notRunning else {
            print("the demo is not running, so the tapper stays in Settings")
            return
        }
        demo.activate()
        guard demo.wait(for: .runningForeground, timeout: 10) else {
            throw TapperError.action("the demo would not come to the front")
        }
        print("the demo is in front")
    }
}
