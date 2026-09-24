import AuthenticationServices
import UIKit

/// Opens a login in an `ASWebAuthenticationSession` and hands back the
/// redirect it caught.
///
/// The session catches any URL whose scheme is the app's bundle identifier,
/// lowercased, so the app registers no URL type for it. It is ephemeral, so
/// it shares no cookies with Safari and iOS shows no consent alert before it.
@objc(AuthSessionPlugin)
public final class AuthSessionPlugin: NSObject {
    private static let lock = NSLock()
    private static var pending: String?
    private static var session: ASWebAuthenticationSession?
    private static let anchor = WindowAnchor()

    @objc public func begin(_ url: String) {
        Self.lock.withLock { Self.pending = nil }
        guard let target = URL(string: url),
            let scheme = Bundle.main.bundleIdentifier?.lowercased()
        else { return }
        DispatchQueue.main.async {
            let session = ASWebAuthenticationSession(url: target, callbackURLScheme: scheme) {
                redirect, _ in
                Self.lock.withLock {
                    if let redirect { Self.pending = redirect.absoluteString }
                    Self.session = nil
                }
            }
            session.prefersEphemeralWebBrowserSession = true
            session.presentationContextProvider = Self.anchor
            Self.lock.withLock { Self.session = session }
            session.start()
        }
    }

    @objc public func takeRedirect() -> String? {
        Self.lock.withLock {
            let redirect = Self.pending
            Self.pending = nil
            return redirect
        }
    }
}

private final class WindowAnchor: NSObject, ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        return scenes.flatMap(\.windows).first(where: \.isKeyWindow)
            ?? scenes.first.map { ASPresentationAnchor(windowScene: $0) }
            ?? ASPresentationAnchor()
    }
}
