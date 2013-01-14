(ns marianoguerra.friend-json-workflow
  (:use [cemerick.friend.util :only (gets)])

  (:require
    [cemerick.friend :as friend]
    (cemerick.friend [workflows :as workflows]
                     [credentials :as creds])
    [clojure.data.json :as json]))

(defn json-response [data & [status]]
  "return a ring json response with data serialized to json and status (200 by
  default)"
  {:status (or status 200)
   :headers {"Content-Type" "application/json"}
   :body (json/json-str data)})

(defn unauthorized-handler [thing]
  "handler when authorization fails"
  (json-response {:ok false :reason "unauthorized"} 403))

(defn login-failed [request]
  "handler when authentication fails"
  (json-response {:ok false :reason "authentication failed"} 401))

(def logout
  "handler to remove session"
  (friend/logout (fn [request]
                   (json-response {:ok true :reason "logged out"}))))

(defn handle-session [request]
  "generic session handler, handles GET,POST and DELETE on session"
  (let [method (:request-method request)
        auth-data (friend/current-authentication)]
    (if auth-data
      (case method
        :post (json-response auth-data)
        :get (json-response auth-data)
        :delete (logout request)
        ; default
        (json-response {:ok false
                        :reason (str "invalid method " method)}
                       405))
      ; else
      (json-response {:ok false :reason "unauthorized"} 401))))

(defn json-login
  "json auth workflow implementation for friend"
  [& {:keys [login-uri credential-fn login-failure-handler] :as form-config}]
  (fn [{:keys [uri request-method body] :as request}]
    (when (and (= (gets :login-uri form-config (::friend/auth-config request)) uri)
               (= :post request-method))
      (let [{:keys [username password] :as creds} (json/read-json (slurp body))]
        (if-let [user-record (and username password
                                  ((gets :credential-fn form-config
                                         (::friend/auth-config request))
                                   (with-meta creds {::friend/workflow :json-login})))]
          (workflows/make-auth user-record
                               {::friend/workflow :json-login
                                ::friend/redirect-on-auth? false})

          ((or (gets :login-failure-handler form-config
                     (::friend/auth-config request))
               #'login-failed)

           (update-in request [::friend/auth-config] merge form-config)))))))

(defn wrap-require-authenticated [handler]
  "utility to require user to be authenticated to access the endpoint"
  (fn [request]
    (if (friend/current-authentication)
      (handler request)
      (unauthorized-handler nil))))
