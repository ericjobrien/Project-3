import axios from "axios";
import config from "../config";
import store from "../store/Store";
import { Button, OverlayTrigger, Popover, } from "react-bootstrap";
import { useEffect, useState } from "react";




export default function Notification(props){
    const [unreadNotifications, setUnreadNotifications] = useState([]);

    useEffect(()=> {
        getUnread();
        async function getUnread(){
            var unread;
            var user;
            await axios
                    .get(`${config.url}users/`, {
                        headers: {
                            token: store.getState().userReducer.token,
                            userId: store.getState().userReducer.userId,
                        },
                    })
                    .then((response) => {
                        user = response.data;
                        console.log(user);
                    })
                    .catch((error) => console.error(`Error: ${error}`));
        
                    await axios
                    .get(`${config.url}notifications/unread/` + user.userId)
                    .then((response) => {
                        unread = response.data;
                        setUnreadNotifications(unread);
                        console.log(unread);
                    })
                    .catch((error) => console.error(`Error: ${error}`));
                    return unread;

                    
        }
    },[])


    return(unreadNotifications ?
        <div>
            <div>
            {unreadNotifications.length > 0 ? (
                    unreadNotifications.map((noti) => (
                    <div style = {{backgroundColor : "black"}} key = {noti.notif_id}>
                        <p>
                            {noti.subject}
                        </p>
                        <p>
                            {noti.notif_text}
                        </p>
                        <p>
                            {noti.date}
                        </p>
                    </div>
                    ))
                ) : (
                    <h4 style={{ color: "white" }}>No notifications</h4>
                )}
                
            </div>
            {/* <OverlayTrigger
            trigger="click"
            key="left"
            placement="left"
            overlay={
            <Popover id={`popover-positioned-left`}>
                <Popover.Header as="h3">{`Notifications`}</Popover.Header>
                <Popover.Body className="popover-notifications">
                {unreadNotifications.length > 0 ? (
                    unreadNotifications.map((noti) => (
                    <p>
                        {noti}
                    </p>
                    ))
                ) : (
                    <h4 style={{ color: "white" }}>No notifications</h4>
                )}
                </Popover.Body>
            </Popover>}  />
            <Button variant="secondary">Popover on </Button>
            <OverlayTrigger/> */}
        </div>: <h1>
            loading
        </h1>
    );
}
